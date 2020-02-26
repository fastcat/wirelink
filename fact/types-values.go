package fact

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/google/uuid"
	"github.com/pkg/errors"

	"github.com/fastcat/wirelink/util"
)

// IPPortValue represents an IP:port pair as an Attribute of a Subject
type IPPortValue struct {
	IP   net.IP
	Port int
}

// *IPValue must implement Value
// same pointer criteria as for PeerSubject
var _ Value = &IPPortValue{}

// MarshalBinary returns the normalized binary representation
func (ipp *IPPortValue) MarshalBinary() ([]byte, error) {
	normalized := util.NormalizeIP(ipp.IP)
	ret := make([]byte, len(normalized)+2)
	copy(ret, normalized)
	binary.BigEndian.PutUint16(ret[len(normalized):], uint16(ipp.Port))
	return ret, nil
}

// UnmarshalBinary implements BinaryUnmarshaler
func (ipp *IPPortValue) UnmarshalBinary(data []byte) error {
	// IMPORTANT: because we may be parsing from a packet buffer, we MUST NOT
	// keep a reference to the data buffer after we return
	if len(data) == net.IPv4len+2 {
		ipp.IP = net.IP(util.CloneBytes(data[0:net.IPv4len]))
		ipp.Port = int(binary.BigEndian.Uint16(data[net.IPv4len:]))
	} else if len(data) == net.IPv6len+2 {
		ipp.IP = net.IP(util.CloneBytes(data[0:net.IPv6len]))
		ipp.Port = int(binary.BigEndian.Uint16(data[net.IPv6len:]))
	} else {
		return errors.Errorf("ipv4 + port should be %d bytes, not %d", net.IPv4len+2, len(data))
	}
	return nil
}

// DecodeFrom implements Decodable
func (ipp *IPPortValue) DecodeFrom(lengthHint int, reader io.Reader) error {
	if lengthHint == net.IPv4len+2 {
		return util.DecodeFrom(ipp, net.IPv4len+2, reader)
	} else if lengthHint == net.IPv6len+2 {
		return util.DecodeFrom(ipp, net.IPv6len+2, reader)
	} else {
		return errors.Errorf("Invalid length hint for for IPPortValue: %v", lengthHint)
	}
}

func (ipp *IPPortValue) String() string {
	return fmt.Sprintf("%v:%v", ipp.IP, ipp.Port)
}

// IPNetValue represents some IP+Mask as an Attribute of a Subject
type IPNetValue struct {
	net.IPNet
}

// *IPNetValue must implement Value
// same pointer criteria as for PeerSubject
var _ Value = &IPNetValue{}

// MarshalBinary gives the binary representation of the ip and cidr prefix
func (ipn IPNetValue) MarshalBinary() ([]byte, error) {
	ipNorm := util.NormalizeIP(ipn.IP)
	ones, _ := ipn.Mask.Size()
	ret := make([]byte, len(ipNorm), len(ipNorm)+1)
	copy(ret, ipNorm)
	ret = append(ret, uint8(ones))
	return ret, nil
}

// UnmarshalBinary implements BinaryUnmarshaler
func (ipn *IPNetValue) UnmarshalBinary(data []byte) error {
	// IMPORTANT: because we may be parsing from a packet buffer, we MUST NOT
	// keep a reference to the data buffer after we return
	if len(data) == net.IPv4len+1 {
		ipn.IP = net.IP(util.CloneBytes(data[0:net.IPv4len]))
		ipn.Mask = net.CIDRMask(int(data[net.IPv4len]), 8*net.IPv4len)
	} else if len(data) == net.IPv6len+1 {
		ipn.IP = net.IP(util.CloneBytes(data[0:net.IPv6len]))
		ipn.Mask = net.CIDRMask(int(data[net.IPv6len]), 8*net.IPv6len)
	} else {
		return errors.Errorf("ipv4 + cidr should be %d bytes, not %d", net.IPv4len+1, len(data))
	}
	return nil
}

// DecodeFrom implements Decodable
func (ipn *IPNetValue) DecodeFrom(lengthHint int, reader io.Reader) error {
	if lengthHint == net.IPv4len+1 {
		return util.DecodeFrom(ipn, net.IPv4len+1, reader)
	} else if lengthHint == net.IPv6len+1 {
		return util.DecodeFrom(ipn, net.IPv6len+1, reader)
	} else {
		return errors.Errorf("Invalid length hint for for IPNetValue: %v", lengthHint)
	}
}

// IPNetValue inherits Stringer from IPNet

// EmptyValue is currently used as a placeholder in Membership facts
type EmptyValue struct{}

var _ Value = EmptyValue{}

// MarshalBinary always returns an empty slice for EmptyValue
func (v EmptyValue) MarshalBinary() ([]byte, error) {
	return []byte{}, nil
}

// DecodeFrom implements Decodable
func (v EmptyValue) DecodeFrom(lengthHint int, reader io.Reader) error {
	return nil
}

func (v EmptyValue) String() string {
	return "<empty>"
}

// UUIDValue represents a UUID, often used as a random marker or tag
type UUIDValue struct {
	uuid.UUID
}

// UUID package doesn't provide this constant for us
const uuidLen = 16

// prove to ourselves it's correct
var _ = uuid.UUID([uuidLen]byte{})

// UUIDValue must implement Value
var _ Value = &UUIDValue{}

// UUIDValue inherits its MarshalBinary from UUID

// DecodeFrom implements Decodable
func (u *UUIDValue) DecodeFrom(lengthHint int, reader io.Reader) error {
	return util.DecodeFrom(u, uuidLen, reader)
}

// UUIDValue inherits its String(er) from UUID
