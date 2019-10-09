package fact

import (
	"encoding/binary"
	"fmt"
	"net"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/fastcat/wirelink/util"
)

// Subject is the subject of a Fact
type Subject interface {
	fmt.Stringer
	Bytes() []byte
}

// Value represents the value of a Fact
type Value interface {
	fmt.Stringer
	Bytes() []byte
}

// Attribute is a byte identifying what aspect of a Subject a Fact describes
type Attribute byte

// PeerSubject is a subject that is a peer identified via its public key
type PeerSubject struct {
	wgtypes.Key
}

// Bytes gives the binary representation of a peer's public key
func (s *PeerSubject) Bytes() []byte {
	return s.Key[:]
}

// *PeerSubject must implement Subject
// we do this with the pointer because if we do it with the struct, the pointer
// matches too, and that confuses things
var _ Subject = &PeerSubject{}

// IPPortValue represents an IP:port pair as an Attribute of a Subject
type IPPortValue struct {
	IP   net.IP
	Port int
}

// IPValue must implement Value
// same pointer criteria as for PeerSubject
var _ Value = &IPPortValue{}

// Bytes returns the normalized binary representation
func (ipp *IPPortValue) Bytes() []byte {
	normalized := util.NormalizeIP(ipp.IP)
	ret := make([]byte, len(normalized)+2)
	copy(ret, normalized)
	binary.BigEndian.PutUint16(ret[len(normalized):], uint16(ipp.Port))
	return ret
}

func (ipp *IPPortValue) String() string {
	return fmt.Sprintf("%v:%v", ipp.IP, ipp.Port)
}

// IPNetValue represents some IP+Mask as an Attribute of a Subject
type IPNetValue struct {
	net.IPNet
}

// IPNetValue must implement Value
var _ Value = IPNetValue{}

// Bytes gives the binary representation of the ip and cidr prefix
func (ipn IPNetValue) Bytes() []byte {
	ipnorm := util.NormalizeIP(ipn.IP)
	ones, _ := ipn.Mask.Size()
	ret := make([]byte, len(ipnorm), len(ipnorm)+1)
	copy(ret, ipnorm)
	ret = append(ret, uint8(ones))
	return ret
}

func (ipn IPNetValue) String() string {
	return ipn.IPNet.String()
}

// EmptyValue is used to represent facts of AttributeUnknown with a zero length value,
// which indicate just that a remote peer is alive and talking to us
type EmptyValue struct{}

var _ Value = EmptyValue{}

// Bytes always returns an empty slice for EmptyValue
func (v EmptyValue) Bytes() []byte {
	return []byte{}
}

func (v EmptyValue) String() string {
	return "<empty>"
}
