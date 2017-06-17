package tcpdump

import "regexp"

var packetPattern = regexp.MustCompile(`(?P<from>.+)\s+>\s+(?P<to>.+):\s+tcp\s+\d+\n((?s)(?P<packet>.+))\n`)

type Packet struct {
	from    string
	to      string
	payload []byte
}

func ParseTCPPacket(packet []byte) *Packet {
	r := packetPattern.FindSubmatch(packet)
	names := packetPattern.SubexpNames()

	p := &Packet{}
	for k, v := range r {
		switch names[k] {
		case "from":
			p.from = string(v)
		case "to":
			p.to = string(v)
		case "packet":
			p.payload = v
		}
	}
	return p
}

func (p *Packet) GetFrom() string {
	return p.from
}

func (p *Packet) GetTo() string {
	return p.to
}

func (p *Packet) GetPayload() []byte {
	return p.payload
}
