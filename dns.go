package dns

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"

	"github.com/sanity-io/litter"
)

type Header struct {
	ID             uint16
	Flags          uint16
	NumQuestions   uint16
	NumAnswers     uint16
	NumAuthorities uint16
	NumAdditionals uint16
}

func (h Header) Encode() []byte {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, h)
	return buf.Bytes()
}

func (h *Header) Decode(r *bufio.Reader) error {
	return binary.Read(r, binary.BigEndian, h)
}

type Class uint16

const (
	ClassIN = Class(1)
)

type Type uint16

const (
	TypeA = Type(1)
)

type Question struct {
	Name  []byte
	Type  Type
	Class Class
}

func (q Question) Encode() []byte {
	var buf bytes.Buffer
	_, _ = buf.Write(EncodeName(q.Name))
	_ = binary.Write(&buf, binary.BigEndian, struct {
		Type  Type
		Class Class
	}{
		Type:  q.Type,
		Class: q.Class,
	})
	return buf.Bytes()
}

func (q *Question) Decode(r *bufio.Reader) error {
	name, err := DecodeName(r)
	if err != nil {
		return err
	}
	var aux struct {
		Type  Type
		Class Class
	}
	if err := binary.Read(r, binary.BigEndian, &aux); err != nil {
		return err
	}
	q.Name = name
	q.Type = aux.Type
	q.Class = aux.Class
	return nil
}

func EncodeName(name []byte) []byte {
	var b []byte
	for _, part := range bytes.Split(name, []byte(".")) {
		b = append(b, byte(len(part)))
		b = append(b, part...)
	}
	b = append(b, 0x00)
	return b
}

func DecodeName(r *bufio.Reader) ([]byte, error) {
	part := make([]byte, 255)
	var name []byte
	for {
		b, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		if b == 0x00 {
			break
		}
		if b&0b1100_0000 != 0 {
			return nil, fmt.Errorf("compression not implemented")
		}
		if _, err := io.ReadFull(r, part[:b]); err != nil {
			return nil, err
		}
		if len(name) > 0 {
			name = append(name, '.')
		}
		name = append(name, part[:b]...)
	}
	return name, nil
}

type Query struct {
	ID     uint16
	Domain string
	Type   Type
}

func (q Query) Encode() []byte {
	var buf bytes.Buffer
	h := Header{
		ID:           q.ID,
		NumQuestions: 1,
		Flags:        1 << 8, // RECURSION_DESIRED
	}
	buf.Write(h.Encode())
	q2 := Question{
		Name:  []byte(q.Domain),
		Type:  q.Type,
		Class: ClassIN,
	}
	buf.Write(q2.Encode())
	return buf.Bytes()
}

func SendQuery(addr string, q Query) (string, error) {
	if q.ID == 0 {
		q.ID = uint16(rand.Intn(math.MaxUint16))
	}
	remote, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return "", err
	}
	conn, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if _, err := conn.Write(q.Encode()); err != nil {
		return "", err
	}
	r := bufio.NewReader(conn)
	var p Packet
	if err := p.Decode(r); err != nil {
		return "", err
	}
	litter.Dump(p)
	return "", nil
}

type Record struct {
	Name  []byte
	Type  Type
	Class Class
	TTL   uint32
	Data  []byte
}

func (r *Record) Decode(br *bufio.Reader) error {
	name, err := DecodeName(br)
	if err != nil {
		return err
	}
	var aux struct {
		Type    Type
		Class   Class
		TTL     uint32
		DataLen uint16
	}
	if err := binary.Read(br, binary.BigEndian, &aux); err != nil {
		return err
	}
	r.Name = name
	r.Type = aux.Type
	r.Class = aux.Class
	r.TTL = aux.TTL
	r.Data = make([]byte, aux.DataLen)
	if _, err := io.ReadFull(br, r.Data); err != nil {
		return err
	}
	return nil
}

type Packet struct {
	Header      Header
	Questions   []Question
	Answers     []Record
	Authorities []Record
	Additionals []Record
}

func (p *Packet) Decode(r *bufio.Reader) error {
	if err := p.Header.Decode(r); err != nil {
		return err
	}
	for i := uint16(0); i < p.Header.NumQuestions; i++ {
		var q Question
		if err := q.Decode(r); err != nil {
			return err
		}
		p.Questions = append(p.Questions, q)
	}
	for i := uint16(0); i < p.Header.NumAnswers; i++ {
		var rec Record
		if err := rec.Decode(r); err != nil {
			return err
		}
		p.Answers = append(p.Answers, rec)
	}
	for i := uint16(0); i < p.Header.NumAuthorities; i++ {
		var rec Record
		if err := rec.Decode(r); err != nil {
			return err
		}
		p.Authorities = append(p.Authorities, rec)
	}
	for i := uint16(0); i < p.Header.NumAdditionals; i++ {
		var rec Record
		if err := rec.Decode(r); err != nil {
			return err
		}
		p.Additionals = append(p.Additionals, rec)
	}
	return nil
}
