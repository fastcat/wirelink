# Wirelink Protocol

## On-Wire Format

Each UDP packet on the wire has the following payload:

* Attribute (1 byte)
* TTL (1 byte)
* Subject length (1 byte)
* Value length (1 byte)
* Subject (N bytes)
* Value (N bytes)

The interpretation & expectations of subject & value depend on the attribute.

All values are in network byte order if unspecified.

## Attributes

The following attributes are defined as 1 byte ASCII values:

* `e`: `EndpointV4`: Value is a 4 byte IPv4 address followed by a two byte UDP
  port
* `E`: `EndpointV6`: Value is a 16 byte IPv6 address followed by a two byte UDP
  port
* `a`: `AllowedCidrV4`: Value is a 4 byte IPv4 network followed by a 1 byte
  CIDR prefix length
* `A`: `AllowedCidrV6`: Value is a 16 byte IPv6 network followed by a 1 byte
  CIDR prefix length
* `S`: `SignedGroup`: Value is a signed group of facts (see below)

## Subjects

Currently all attributes use a single kind of subject, namely a wireguard
public key, in binary form (32 bytes). For most attributes, this identifies the
peer being described by the attribute. For the `SignedGroup` attribute, this
represence the key of the _source_ peer against which the signature should be
verified.

## Values

`EndpointV4` and `EndpointV6` are IP addresses of the appropriate length
followed by a UDP port number. For example, an `EndpointV4` of `10.0.0.1:51280`
would be represented as:

    0x0A 0x00 0x00 0x01 0xC8 0x50

Similarly `AllowedCidrV4` and `AllowedCidrV6` are IP addresses of the
appropriate length followed by the CIDR prefix length. For example, an
`AllowedCidrV4` of `10.0.0.0/24` would be represented as:

    0x0A 0x00 0x00 0x00 0x18

## Signed Groups

Signed groups are used to combine two goals:

1. Securing received information, esp. that which can authenticate new peers
2. Reducing network activity (esp WiFi/LTE radios on battery powered devices)
   by combining several facts into a single packet

The wire form of the value is:

* Nonce (24 bytes, for XChaCha20-Poly1305)
* Authentication Tag (16 bytes, for XChaCha20-Poly1305)
* Inner Facts (N bytes)

The `Subject` of a `SignedGroup` is the (public) key that signed it. The value
is the signature tag (16 bytes) followed by a sequence of concatenated facts.
Note that this means that a corrupted fact will also prevent parsing following
facts in the group.

Signing (authentication) is done with the XChaCha20-Poly1305 AEAD construction,
the same as wireguard itself uses, where we derive the private key for the
construction using the standard Curve25519 format. Within the AEAD
construction, no plaintext is given and the concatenated facts are provided as
the additional (unencrypted) data. Encrypting the facts is not useful since
they are only ever sent in the first place over the encrypted wireguard link.

_Trust_ of the signed data is considered separately from _authentication_. For
example, a packet may have an authentic signature, but be from an untrusted
peer, or the contained facts may have attributes we do not trust that peer to
provide. Authenticating the data just considers authenticating the signature,
and verifying it against the source address (as is done for unsigned facts).

A `SignedGroup` value _MUST NOT_ itself contain a `SignedGroup` fact. Such a
packet is invalid will be ignored.
