package dns

import (
	"bytes"
	"encoding/binary"
	"io"
)

type Header struct {
	ID             uint16
	Flags          uint16
	NumQuestions   uint16
	NumAnswers     uint16
	NumAuthorities uint16
	NumAdditionals uint16
}

func (h Header) Write(w io.Writer) error {
	return binary.Write(w, binary.BigEndian, h)
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

func (q Question) Write(w io.Writer) error {
	if _, err := w.Write(EncodeQueryName(q.Name)); err != nil {
		return err
	}
	return binary.Write(w, binary.BigEndian, struct {
		Type  Type
		Class Class
	}{
		Type:  q.Type,
		Class: q.Class,
	})
}

type Query struct {
	ID     uint16
	Domain string
	Type   Type
}

func (q Query) Write(w io.Writer) error {
	h := Header{
		ID:           q.ID,
		NumQuestions: 1,
		Flags:        1 << 8, // RECURSION_DESIRED
	}
	if err := h.Write(w); err != nil {
		return err
	}
	q2 := Question{
		Name:  []byte(q.Domain),
		Type:  q.Type,
		Class: ClassIN,
	}
	return q2.Write(w)
}
