package peerfacts

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/fastcat/wirelink/fact"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// PeerSubject is a subject that is a peer identified via its public key
type PeerSubject struct {
	wgtypes.Key
}

// Bytes gives the binary representation of a peer's public key
func (s PeerSubject) Bytes() []byte {
	return s.Key[:]
}

// PeerSubject must implement Subject
var _ fact.Subject = PeerSubject{}

// IPPortValue represents an IP:port pair as an Attribute of a Subject
type IPPortValue struct {
	IP   net.IP
	Port int
}

// IPValue must implement Value
var _ fact.Value = IPPortValue{}

// Bytes returns the normalized binary representation
func (ipp IPPortValue) Bytes() []byte {
	normalized := ipp.IP.To4()
	if normalized == nil {
		normalized = ipp.IP.To16()
	}
	ret := make([]byte, len(normalized)+2)
	copy(ret, normalized)
	binary.BigEndian.PutUint16(ret[len(normalized):], uint16(ipp.Port))
	return normalized
}

func (ipp IPPortValue) String() string {
	return fmt.Sprintf("%v:%v", ipp.IP, ipp.Port)
}

// IPNetValue represents some IP+Mask as an Attribute of a Subject
type IPNetValue struct {
	net.IPNet
}

// IPNetValue must implement Value
var _ fact.Value = IPNetValue{}

// Bytes gives the binary representation of the ip and cidr prefix
func (ipn IPNetValue) Bytes() []byte {
	ipnorm := ipn.IP.To4()
	if ipnorm == nil {
		ipnorm = ipn.IP.To16()
	}
	ones, _ := ipn.Mask.Size()
	ret := make([]byte, len(ipnorm), len(ipnorm)+1)
	copy(ret, ipnorm)
	ret = append(ret, uint8(ones))
	return ret
}

func (ipn IPNetValue) String() string {
	return ipn.IPNet.String()
}
