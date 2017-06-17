package tcpdump

import (
	"bufio"
	"bytes"
	"log"
	"os/exec"
	"regexp"
)

var headerPattern = regexp.MustCompile(`(?m)^IP6?\s+.*\n`)

type Tcpdump struct {
	args []string
}

// This option makes the tcpdump result as followings.
//
// IP 192.168.1.1.65261 > 192.168.1.2.443: tcp 110
// .5q     t^..P.&...E.....@.@.;<...nh........&...I^.....{......
// [Df.P.S.....i.......r...i.....hO....d...M0..... .,4..]..M...Yp..J.Q..$...G..    B....X.W.:..(h..y........@.....fA......-
var opts = []string{"tcp", "-i", "any", "-A", "-t", "-n", "-q", "-s", "0"}

func NewTcpdump(extraArgs []string) *Tcpdump {
	return &Tcpdump{
		args: append(opts, extraArgs...),
	}
}

func (td *Tcpdump) TCPEach() chan []byte {

	cmd := exec.Command("tcpdump", td.args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatalln(err)
	}

	packetCh := make(chan []byte)

	go func() {
		cmd.Start()
		scanner := bufio.NewScanner(stdout)
		scanner.Split(splitTCPPacket)
		for scanner.Scan() {
			packetCh <- scanner.Bytes()
		}
		close(packetCh)
	}()
	return packetCh
}

func splitTCPPacket(data []byte, atEOF bool) (int, []byte, error) {

	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}

	r := headerPattern.FindAllIndex(data, -1)
	for _, rr := range r {
		for _, pos := range rr {
			if pos >= 0 {
				if bytes.Contains(data, []byte{73, 80, 54}) { // "IP6"
					// "abc def IP6 xxx yyy" -> "'abc def', 'xxx yyy'"
					return pos + len("IP6") + 1, data[0:pos], nil
				}
				// "abc def IP xxx yyy" -> "'abc def', 'xxx yyy'"
				return pos + len("IP") + 1, data[0:pos], nil
				// return pos + 1, data[0:pos], nil
			}
		}
	}
	// If we're at EOF, we have a final, non-terminated line. Return it.
	if atEOF {
		return len(data), data, nil
	}
	// Request more data.
	return 0, nil, nil
}
