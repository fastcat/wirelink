package fact

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"time"

	"github.com/fastcat/wirelink/util"
)

// a decodeHinter is expected to initialize the Subject and Value fields of the
// given Fact to the correct types, and return the expected length (in bytes)
// of the encoded value, or -1 if that length is unknown or variable.
type decodeHinter = func(*Fact) (valueLength int)

// decodeHints provides a lookup table for how to decode each valid attribute value
var decodeHints = map[Attribute]decodeHinter{
	AttributeAlive: func(f *Fact) int {
		// Modern ping packet with boot id embedded in value
		f.Subject = &PeerSubject{}
		f.Value = &UUIDValue{}
		return uuidLen
	},
	AttributeEndpointV4: func(f *Fact) int {
		f.Subject = &PeerSubject{}
		f.Value = &IPPortValue{}
		return net.IPv4len + 2
	},
	AttributeEndpointV6: func(f *Fact) int {
		f.Subject = &PeerSubject{}
		f.Value = &IPPortValue{}
		return net.IPv6len + 2
	},
	AttributeAllowedCidrV4: func(f *Fact) int {
		f.Subject = &PeerSubject{}
		f.Value = &IPNetValue{}
		return net.IPv4len + 1
	},
	AttributeAllowedCidrV6: func(f *Fact) int {
		f.Subject = &PeerSubject{}
		f.Value = &IPNetValue{}
		return net.IPv6len + 1
	},

	AttributeMember: func(f *Fact) int {
		// member attrs don't have a value
		f.Subject = &PeerSubject{}
		f.Value = &EmptyValue{}
		return 0
	},
	AttributeMemberMetadata: func(f *Fact) int {
		f.Subject = &PeerSubject{}
		f.Value = &MemberMetadata{}
		return 0
	},

	AttributeSignedGroup: func(f *Fact) int {
		f.Subject = &PeerSubject{}
		f.Value = &SignedGroupValue{}
		// this is a variable length, expected to consume everything until EOF
		return -1
	},
}

// DecodeFrom implements Decodable
func (f *Fact) DecodeFrom(_ int, now time.Time, reader util.ByteReader) error {
	var err error

	attrByte, err := reader.ReadByte()
	if err != nil {
		return fmt.Errorf("unable to read attribute byte from packet: %w", err)
	}
	f.Attribute = Attribute(attrByte)

	hinter, ok := decodeHints[f.Attribute]
	if !ok {
		if f.Attribute == AttributeUnknown {
			// AttributeUnknown used to be used for ping packets, this has been removed
			return fmt.Errorf("legacy AttributeUnknown ping packet not supported")
		}
		return fmt.Errorf("unrecognized attribute 0x%02x", byte(f.Attribute))
	}

	ttl, err := binary.ReadUvarint(reader)
	if err != nil {
		return fmt.Errorf("unable to read ttl from packet: %w", err)
	}
	// clamp TTL to valid range
	if ttl > math.MaxUint16 {
		return fmt.Errorf("received TTL outside range: %v", ttl)
	}
	f.Expires = now.Add(time.Duration(ttl) * timeScale)

	valueLength := hinter(f)

	err = f.Subject.DecodeFrom(0, reader)
	if err != nil {
		return fmt.Errorf("failed to unmarshal fact subject from packet for %v: %w", f.Attribute, err)
	}
	err = f.Value.DecodeFrom(valueLength, reader)
	if err != nil {
		return fmt.Errorf("failed to unmarshal fact value from packet for %v: %w", f.Attribute, err)
	}

	return nil
}
