package config

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

// mostly for experimenting with what errors the `net` package provides
// it seems that basically everything is a DNSError other than the empty string
func Test_DnsErrors(t *testing.T) {
	// this one _ought_ to give some kind of parse or range error ... but it doesn't
	ips, err := net.LookupIP("256.256.256.256") // gives no such host
	assert.NotNil(t, err)
	assert.Len(t, ips, 0)
	assert.IsType(t, &net.DNSError{}, err)
}
