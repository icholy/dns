package dns

import (
	"testing"

	"gotest.tools/v3/assert"
)

func TestHeaderEncode(t *testing.T) {
	h := Header{
		ID:           0x1314,
		NumQuestions: 1,
	}
	assert.DeepEqual(t, string(h.Encode()), "\x13\x14\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00")
}

func TestEncodeQueryName(t *testing.T) {
	name := EncodeQueryName([]byte("google.com"))
	assert.DeepEqual(t, string(name), "\x06google\x03com\x00")
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
	q := Query{Domain: "google.com", Type: TypeA}
	ip, err := SendQuery("8.8.8.8:53", q)
	assert.NilError(t, err)
	t.Logf("Resolved: %s", ip)
}
