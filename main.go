package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"time"

	"strings"

	"github.com/hiroakis/go-sql-sniffer/tcpdump"
)

func write(str string, f *os.File) {
	buf := bytes.NewBufferString(str)
	io.Copy(f, buf)
}

type SQLPacket struct {
	UnixTime int64  `json:"unixtime"`
	DateTime string `json:"datetime"`
	From     string `json:"from"`
	To       string `json:"to"`
	SQL      string `json:"sql"`
}

const datetimeFormat = "2006-01-02 15:04:05"

var sqlPattern = regexp.MustCompile(`(?si)(select|insert|update|delete|show|create|alter|begin|commit|rollback)`)

func findSQL(payload []byte) string {
	loc := sqlPattern.FindIndex(payload)
	if len(loc) == 0 {
		return ""
	}
	return string(payload[loc[0]:])
}

func NewSQLPacket(packet tcpdump.Packet) *SQLPacket {
	sql := findSQL(packet.GetPayload())
	if sql == "" {
		return nil
	}

	return &SQLPacket{
		UnixTime: time.Now().Unix(),
		DateTime: time.Now().Format(datetimeFormat),
		From:     packet.GetFrom(),
		To:       packet.GetTo(),
		SQL:      sql,
	}
}

func (s *SQLPacket) jsonify() string {
	b, _ := json.Marshal(s)
	return string(b)
}

func (s *SQLPacket) toCsv() string {
	escapedSQL := strings.Replace(s.SQL, "\"", "\\\"", -1)
	return fmt.Sprintf(`"%d","%s","%s","%s","%s"`, s.UnixTime, s.DateTime, s.From, s.To, escapedSQL)
}

func (s *SQLPacket) toTsv() string {
	escapedSQL := strings.Replace(s.SQL, "\"", "\\\"", -1)
	return fmt.Sprintf("\"%d\"\t\"%s\"\t\"%s\"\t\"%s\"\t\"%s\"", s.UnixTime, s.DateTime, s.From, s.To, escapedSQL)
}

func main() {

	var (
		dst    bool
		src    bool
		port   string
		file   string
		format string
	)
	flag.StringVar(&port, "port", "3306", "The SQL traffic port.")
	flag.BoolVar(&dst, "dst", true, "The dst flag. See man tcpdump.")
	flag.BoolVar(&src, "src", false, "The src flag. See man tcpdump.")
	flag.StringVar(&file, "file", "", "If you run with -file, the packet data will be saved to specified file.")
	flag.StringVar(&format, "format", "json", "The output format. You can set json, csv and tsv.")
	flag.Parse()

	var opts []string
	if src {
		opts = []string{"src", "port", port}
	} else {
		opts = []string{"dst", "port", port}
	}

	var f *os.File
	if file == "" {
		f = os.Stdout
	} else {
		var err error
		f, err = os.Create(file)
		if err != nil {
			log.Fatalf("Couldn't create file: %s", file)
		}
	}

	defer func() {
		if f != nil {
			f.Close()
		}
	}()

	td := tcpdump.NewTcpdump(opts)

	for packet := range td.TCPEach() {
		p := tcpdump.ParseTCPPacket(packet)

		sql := NewSQLPacket(*p)
		if sql == nil {
			continue
		}

		var s string
		switch format {
		case "json":
			s = sql.jsonify()
		case "csv":
			s = sql.toCsv()
		case "tsv":
			s = sql.toTsv()
		default:
			s = sql.jsonify()
		}

		io.Copy(f, bytes.NewBufferString(s+"\n"))
	}
}
