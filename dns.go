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

func EncodeQueryName(name []byte) []byte {
	var b []byte
	for _, part := range bytes.Split(name, []byte(".")) {
		b = append(b, byte(len(part)))
		b = append(b, part...)
	}
	b = append(b, 0x00)
	return b
}

func DecodeQueryName(r *bufio.Reader) ([]byte, error) {
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

func (q Question) Encode() []byte {
	var buf bytes.Buffer
	_, _ = buf.Write(EncodeQueryName(q.Name))
	_ = binary.Write(&buf, binary.BigEndian, struct {
		Type  Type
		Class Class
	}{
		Type:  q.Type,
		Class: q.Class,
	})
	return buf.Bytes()
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
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	fmt.Printf("len=%d %s", n, buf[:n])
	return "", nil
}

type Record struct {
	Name  []byte
	Type  Type
	Class Class
	TTL   uint16
	Data  []byte
}
