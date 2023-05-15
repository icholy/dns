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
	TypeNS  = Type(2)
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
	return DecodeName(bufio.NewReader(rs), rs)
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

func BuildQuery(id uint16, domain string, typ Type, flags Flag) *Packet {
	return &Packet{
		Header: Header{
			ID:           id,
			NumQuestions: 1,
			Flags:        flags,
		},
		Questions: []Question{
			{
				Name:  []byte(domain),
				Type:  typ,
				Class: ClassIN,
			},
		},
	}
}

func SendQuery(addr string, q *Packet) (*Packet, error) {
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

func (r Record) Encode() []byte {
	var buf bytes.Buffer
	buf.Write(EncodeName(r.Name))
	data := r.Data
	if r.Type == TypeNS {
		data = EncodeName(data)
	}
	binary.Write(&buf, binary.BigEndian, struct {
		Type    Type
		Class   Class
		TTL     uint32
		DataLen uint16
	}{
		Type:    r.Type,
		Class:   r.Class,
		TTL:     r.TTL,
		DataLen: uint16(len(data)),
	})
	buf.Write(data)
	return buf.Bytes()
}

func (r Record) String() string {
	if r.Type == TypeA {
		return fmt.Sprintf("%s %d %d %s", r.Name, r.Type, r.TTL, ParseIP(r.Data))
	}
	return fmt.Sprintf("%s %d %d %s", r.Name, r.Type, r.TTL, r.Data)
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
	if r.Type == TypeNS {
		name, err := DecodeName(bufio.NewReader(bytes.NewReader(r.Data)), rs)
		if err != nil {
			return err
		}
		r.Data = name
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

func (p *Packet) Encode() []byte {
	var buf bytes.Buffer
	buf.Write(p.Header.Encode())
	for _, q := range p.Questions {
		buf.Write(q.Encode())
	}
	for _, r := range p.Answers {
		buf.Write(r.Encode())
	}
	for _, r := range p.Authorities {
		buf.Write(r.Encode())
	}
	for _, r := range p.Additionals {
		buf.Write(r.Encode())
	}
	return buf.Bytes()
}

func FindRecord(recs []Record, typ Type) (Record, bool) {
	for _, r := range recs {
		if r.Type == typ {
			return r, true
		}
	}
	return Record{}, false
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
	a, ok := FindRecord(pkt.Answers, TypeA)
	if !ok {
		return "", fmt.Errorf("no answers")
	}
	return ParseIP(a.Data), nil
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

func ResolveDomain(domain string, typ Type) (string, error) {
	pkt, err := Resolve(Question{
		Name:  []byte(domain),
		Type:  typ,
		Class: ClassIN,
	})
	if err != nil {
		return "", err
	}
	a, _ := FindRecord(pkt.Answers, typ)
	return ParseIP(a.Data), nil
}

func Resolve(question Question) (*Packet, error) {
	addr := "198.41.0.4:53"
	for {
		fmt.Printf("Querying %s for %s\n", addr, question.Name)
		q := BuildQuery(0, string(question.Name), question.Type, 0)
		pkt, err := SendQuery(addr, q)
		if err != nil {
			return nil, err
		}
		if _, ok := FindRecord(pkt.Answers, question.Type); ok {
			return pkt, nil
		}
		ns, ok := FindRecord(pkt.Additionals, TypeA)
		if ok {
			addr = net.JoinHostPort(ParseIP(ns.Data), "53")
			continue
		}
		auth, ok := FindRecord(pkt.Authorities, TypeNS)
		if !ok {
			return pkt, nil
		}
		host, err := ResolveDomain(string(auth.Data), TypeA)
		if err != nil {
			return nil, err
		}
		addr = net.JoinHostPort(host, "53")
	}
}

func Serve(conn *net.UDPConn) error {
	data := make([]byte, 512)
	for {
		n, addr, err := conn.ReadFromUDP(data)
		if err != nil {
			fmt.Printf("failed to read from connection: %v\n", err)
		}
		var q Packet
		buf := SeekBuffer{data: data[:n]}
		r := bufio.NewReader(bytes.NewReader(data[:n]))
		if err := q.Decode(r, &buf); err != nil {
			fmt.Printf("failed to decode query: %v\n", err)
			continue
		}
		fmt.Printf("Query: %#v\n", q)
		if len(q.Questions) != 1 {
			fmt.Printf("only 1 question allowed, got %d", len(q.Questions))
			continue
		}
		pkt, err := Resolve(q.Questions[0])
		if err != nil {
			fmt.Printf("failed to resolve: %v\n", err)
			continue
		}
		fmt.Printf("Packet: %#v\n", pkt)
		pkt.Header.ID = q.Header.ID
		if _, err := conn.WriteToUDP(pkt.Encode(), addr); err != nil {
			fmt.Printf("failed to write packet: %v", err)
		}
	}
}
