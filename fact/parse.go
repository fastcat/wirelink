package fact

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"
	"net"
	"time"

	"github.com/pkg/errors"
)

type decodeHinter = func(*Fact) (valueLength int)

// decodeHints provides a lookup table for how to decode each valid attribute value
var decodeHints map[Attribute]decodeHinter = map[Attribute]decodeHinter{
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

	AttributeSignedGroup: func(f *Fact) int {
		f.Subject = &PeerSubject{}
		f.Value = &SignedGroupValue{}
		// this is a variable length, have to parse what's coming to see how long
		return -1
	},
}

// DecodeFrom implements Decodable
func (f *Fact) DecodeFrom(lengthHint int, now time.Time, reader io.Reader) error {
	// TODO: generic reader support
	var buf *bytes.Buffer
	var ok bool
	if buf, ok = reader.(*bytes.Buffer); !ok {
		return errors.Errorf("Reading Fact is only supported from a Buffer, not a %T", reader)
	}
	var err error

	attrByte, err := buf.ReadByte()
	if err != nil {
		return errors.Wrap(err, "Unable to read attribute byte from packet")
	}
	f.Attribute = Attribute(attrByte)

	ttl, err := binary.ReadUvarint(buf)
	if err != nil {
		return errors.Wrap(err, "Unable to read ttl from packet")
	}
	// clamp TTL to valid range
	if ttl > math.MaxUint16 {
		return errors.Errorf("Received TTL outside range: %v", ttl)
	}
	f.Expires = now.Add(time.Duration(ttl) * timeScale)

	hinter, ok := decodeHints[f.Attribute]
	if !ok {
		if f.Attribute == AttributeUnknown {
			// AttributeUnknown used to be used for ping packets, this has been removed
			return errors.Errorf("Legacy AttributeUnknown ping packet not supported")
		}
		return errors.Errorf("Unrecognized attribute 0x%02x", byte(f.Attribute))
	}
	valueLength := hinter(f)

	err = f.Subject.DecodeFrom(0, buf)
	if err != nil {
		return errors.Wrapf(err, "Failed to unmarshal fact subject from packet for %v", f.Attribute)
	}
	err = f.Value.DecodeFrom(valueLength, buf)
	if err != nil {
		return errors.Wrapf(err, "Failed to unmarshal fact value from packet for %v", f.Attribute)
	}

	return nil
}
