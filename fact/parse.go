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

// DecodeFrom implements Decodable
func (f *Fact) DecodeFrom(lengthHint int, reader io.Reader) error {
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
	f.Expires = time.Now().Add(time.Duration(ttl) * time.Second)

	var valueLength int

	switch f.Attribute {
	// AttributeUnknown used to be used for ping packets, this has been removed
	case AttributeUnknown:
		return errors.Errorf("Legacy AttributeUnknown ping packet not supported")
	// 	// Legacy ping packet
	// 	subject, err = ParsePeerSubject(p.subject)
	// 	if err != nil {
	// 		return
	// 	}
	// 	if len(p.value) != 0 {
	// 		return nil, errors.Errorf("No-attribute packets must have empty value, not %d", len(p.value))
	// 	}
	// 	value = EmptyValue{}

	case AttributeAlive:
		// Modern ping packet with boot id embedded in value
		f.Subject = &PeerSubject{}
		f.Value = &UUIDValue{}

	case AttributeEndpointV4:
		valueLength = net.IPv4len + 2
		f.Subject = &PeerSubject{}
		f.Value = &IPPortValue{}
	case AttributeEndpointV6:
		valueLength = net.IPv6len + 2
		f.Subject = &PeerSubject{}
		f.Value = &IPPortValue{}
	case AttributeAllowedCidrV4:
		valueLength = net.IPv4len + 1
		f.Subject = &PeerSubject{}
		f.Value = &IPNetValue{}
	case AttributeAllowedCidrV6:
		valueLength = net.IPv6len + 1
		f.Subject = &PeerSubject{}
		f.Value = &IPNetValue{}

	case AttributeMember:
		// member attrs don't have a value
		f.Subject = &PeerSubject{}
		f.Value = &EmptyValue{}

	case AttributeSignedGroup:
		f.Subject = &PeerSubject{}
		f.Value = &SignedGroupValue{}

	default:
		return errors.Errorf("Unrecognized attribute 0x%02x", byte(f.Attribute))
	}

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
