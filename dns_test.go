package dns

import (
	"bufio"
	"bytes"
	"strings"
	"testing"

	"gotest.tools/v3/assert"
)

func TestHeaderEncodeDecode(t *testing.T) {
	encoded := "\x13\x14\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
	// encode
	h := Header{
		ID:           0x1314,
		NumQuestions: 1,
	}
	assert.DeepEqual(t, string(h.Encode()), encoded)
	// decode
	var h2 Header
	r := bufio.NewReader(strings.NewReader(encoded))
	assert.NilError(t, h2.Decode(r))
	assert.DeepEqual(t, h, h2)
}

func TestEncodeDecodeQueryName(t *testing.T) {
	name := []byte("google.com")
	// encode
	encoded := EncodeQueryName(name)
	assert.DeepEqual(t, string(encoded), "\x06google\x03com\x00")
	// decode
	decoded, err := DecodeQueryName(bufio.NewReader(bytes.NewReader(encoded)))
	assert.NilError(t, err)
	assert.DeepEqual(t, string(decoded), string(name))
}

func TestQueryEncode(t *testing.T) {
	q := Query{
		ID:     17611,
		Domain: "example.com",
		Type:   TypeA,
	}
	assert.DeepEqual(t, string(q.Encode()), "D\xcb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01")
}

func TestSendQuery(t *testing.T) {
	t.Skip()
	q := Query{Domain: "google.com", Type: TypeA}
	ip, err := SendQuery("8.8.8.8:53", q)
	assert.NilError(t, err)
	t.Logf("Resolved: %s", ip)
}
