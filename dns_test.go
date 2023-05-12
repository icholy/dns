package dns

import (
	"bytes"
	"testing"

	"gotest.tools/v3/assert"
)

func TestHeaderWrite(t *testing.T) {
	h := Header{
		ID:           0x1314,
		NumQuestions: 1,
	}
	var b bytes.Buffer
	assert.NilError(t, h.Write(&b))
	assert.DeepEqual(t, string(b.Bytes()), "\x13\x14\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00")
}

func TestEncodeQueryName(t *testing.T) {
	name := EncodeQueryName([]byte("google.com"))
	assert.DeepEqual(t, string(name), "\x06google\x03com\x00")
}

func TestQueryWrite(t *testing.T) {
	q := Query{
		ID:     555,
		Domain: "example.com",
		Type:   TypeA,
	}
	var b bytes.Buffer
	assert.NilError(t, q.Write(&b))
	assert.DeepEqual(t, string(b.Bytes()), "D\xcb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01")
}
