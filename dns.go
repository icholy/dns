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
	"strconv"
	"strings"
)

type Header struct {
	ID             uint16
	Flags          Flag
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

type Flag uint16

const (
	FlagRecusion = 1 << 8
)

type Class uint16

const (
	ClassIN = Class(1)
)

type Type uint16

const (
	TypeA   = Type(1)
	TypeTXT = Type(16)
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

func (q *Question) Decode(r *bufio.Reader, rs io.ReadSeeker) error {
	name, err := DecodeName(r, rs)
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

func DecodeCompressedName(r *bufio.Reader, rs io.ReadSeeker, length byte) ([]byte, error) {
	if rs == nil {
		return nil, fmt.Errorf("cannot decompress without seeker")
	}
	// find the pointer
	b, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	pointer := binary.BigEndian.Uint16([]byte{length & 0b0011_1111, b})
	if _, err := rs.Seek(int64(pointer), 0); err != nil {
		return nil, err
	}
	// decode the name
	return DecodeName(bufio.NewReader(rs), nil)
}

func DecodeName(r *bufio.Reader, rs io.ReadSeeker) ([]byte, error) {
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
			part, err := DecodeCompressedName(r, rs, b)
			if err != nil {
				return nil, err
			}
			if len(name) > 0 {
				name = append(name, '.')
			}
			name = append(name, part...)
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

type Query struct {
	Header   Header
	Question Question
}

func BuildQuery(id uint16, domain string, typ Type, flags Flag) Query {
	return Query{
		Header: Header{
			ID:           id,
			NumQuestions: 1,
			Flags:        flags,
		},
		Question: Question{
			Name:  []byte(domain),
			Type:  typ,
			Class: ClassIN,
		},
	}
}

func (q Query) Encode() []byte {
	var buf bytes.Buffer
	buf.Write(q.Header.Encode())
	buf.Write(q.Question.Encode())
	return buf.Bytes()
}

func SendQuery(addr string, q Query) (*Packet, error) {
	if q.Header.ID == 0 {
		q.Header.ID = uint16(rand.Intn(math.MaxUint16))
	}
	remote, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if _, err := conn.Write(q.Encode()); err != nil {
		return nil, err
	}
	var buf SeekBuffer
	r := bufio.NewReader(io.TeeReader(conn, &buf))
	var pkt Packet
	if err := pkt.Decode(r, &buf); err != nil {
		return nil, err
	}
	return &pkt, nil
}

type Record struct {
	Name  []byte
	Type  Type
	Class Class
	TTL   uint32
	Data  []byte
}

func (r *Record) Decode(br *bufio.Reader, rs io.ReadSeeker) error {
	name, err := DecodeName(br, rs)
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

func (p *Packet) Decode(r *bufio.Reader, rs io.ReadSeeker) error {
	if err := p.Header.Decode(r); err != nil {
		return err
	}
	for i := uint16(0); i < p.Header.NumQuestions; i++ {
		var q Question
		if err := q.Decode(r, rs); err != nil {
			return err
		}
		p.Questions = append(p.Questions, q)
	}
	for i := uint16(0); i < p.Header.NumAnswers; i++ {
		var rec Record
		if err := rec.Decode(r, rs); err != nil {
			return err
		}
		p.Answers = append(p.Answers, rec)
	}
	for i := uint16(0); i < p.Header.NumAuthorities; i++ {
		var rec Record
		if err := rec.Decode(r, rs); err != nil {
			return err
		}
		p.Authorities = append(p.Authorities, rec)
	}
	for i := uint16(0); i < p.Header.NumAdditionals; i++ {
		var rec Record
		if err := rec.Decode(r, rs); err != nil {
			return err
		}
		p.Additionals = append(p.Additionals, rec)
	}
	return nil
}

func ParseIP(data []byte) string {
	ip := make([]string, len(data))
	for i, b := range data {
		ip[i] = strconv.Itoa(int(b))
	}
	return strings.Join(ip, ".")
}

func LookupDomain(addr, domain string) (string, error) {
	q := BuildQuery(0, domain, TypeA, FlagRecusion)
	pkt, err := SendQuery(addr, q)
	if err != nil {
		return "", err
	}
	if len(pkt.Answers) == 0 {
		return "", fmt.Errorf("no answers")
	}
	return ParseIP(pkt.Answers[0].Data), nil
}

type SeekBuffer struct {
	data   []byte
	offset int64
}

func (b *SeekBuffer) Seek(offset int64, whence int) (int64, error) {
	if offset < 0 || offset >= int64(len(b.data)) {
		return 0, fmt.Errorf("seek offset out of bounds: %d", offset)
	}
	b.offset = offset
	return offset, nil
}

func (b *SeekBuffer) Read(data []byte) (int, error) {
	n := copy(data, b.data[b.offset:])
	b.offset += int64(n)
	return n, nil
}

func (b *SeekBuffer) Write(data []byte) (int, error) {
	b.data = append(b.data, data...)
	return len(data), nil
}
