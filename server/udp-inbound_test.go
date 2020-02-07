package server

import (
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/fastcat/wirelink/autopeer"
	"github.com/fastcat/wirelink/config"
	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/internal/testutils"
	"github.com/fastcat/wirelink/internal/testutils/facts"
	"github.com/fastcat/wirelink/signing"
	"github.com/fastcat/wirelink/util"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLinkServer_processSignedGroup(t *testing.T) {
	now := time.Now()
	expires := now.Add(FactTTL)

	// this is doing crypto, so we need _real_ keys, not just random bytes
	localPrivKey, localPubKey := testutils.MustKeyPair(t)
	remotePrivKey, remotePubKey := testutils.MustKeyPair(t)
	localSigner := signing.New(&localPrivKey)
	remoteSigner := signing.New(&remotePrivKey)
	properSource := &net.UDPAddr{
		IP:   autopeer.AutoAddress(remotePubKey),
		Port: rand.Intn(65535),
	}
	improperSource := testutils.RandUDP4Addr(t)

	sign := func(f *fact.SignedGroupValue) *fact.SignedGroupValue {
		nonce, tag, err := remoteSigner.SignFor(f.InnerBytes, &localPubKey)
		require.NoError(t, err)
		f.Nonce = nonce
		f.Tag = tag
		return f
	}

	sgvFromBytes := func(t *testing.T, data []byte) *fact.SignedGroupValue {
		return sign(&fact.SignedGroupValue{
			InnerBytes: data,
		})
	}
	svgFromFacts := func(t *testing.T, facts ...*fact.Fact) *fact.SignedGroupValue {
		data := make([]byte, 0)
		for _, f := range facts {
			data = append(data, util.MustBytes(f.MarshalBinaryNow(now))...)
		}
		return sgvFromBytes(t, data)
	}
	rf := func(f *fact.Fact) *ReceivedFact {
		return &ReceivedFact{
			fact:   f,
			source: *properSource,
		}
	}
	corrupt := func(offset int, data []byte) []byte {
		inner := data[offset:]
		// using xor to ensure we change at least one bit, i.e. no matter what random value we get,
		// we will change the target byte
		inner[rand.Intn(len(inner))] ^= byte(1 + rand.Intn(255))
		return data
	}
	corruptSGV := func(f *fact.SignedGroupValue) *fact.SignedGroupValue {
		pos := rand.Intn(len(f.Nonce) + len(f.Tag) + len(f.InnerBytes))
		if pos < len(f.Nonce) {
			t.Logf("Corrupting nonce")
			corrupt(0, f.Nonce[:])
		} else if pos < len(f.Nonce)+len(f.Tag) {
			t.Logf("Corrupting Tag")
			corrupt(0, f.Tag[:])
		} else {
			t.Logf("Corrupting InnerBytes")
			corrupt(0, f.InnerBytes)
		}
		return f
	}
	shorten := func(f *fact.SignedGroupValue) *fact.SignedGroupValue {
		// make sure we both shorten it by at least one byte, and leave at least one byte behind
		end := rand.Intn(len(f.InnerBytes)-1) + 1
		t.Logf("Shortening InnerBytes from %d to %d", len(f.InnerBytes), end)
		f.InnerBytes = f.InnerBytes[:end]
		return f
	}

	type fields struct {
		signer *signing.Signer
	}
	type args struct {
		f      *fact.Fact
		source *net.UDPAddr
	}
	tests := []struct {
		name        string
		fields      fields
		args        args
		assertion   require.ErrorAssertionFunc
		wantPackets []*ReceivedFact
	}{
		{
			"valid empty",
			fields{
				signer: localSigner,
			},
			args{
				&fact.Fact{
					Attribute: fact.AttributeSignedGroup,
					Subject:   &fact.PeerSubject{Key: remotePubKey},
					Value:     sgvFromBytes(t, []byte{}),
				},
				properSource,
			},
			require.NoError,
			[]*ReceivedFact{},
		},
		{
			"valid alive",
			fields{
				signer: localSigner,
			},
			args{
				&fact.Fact{
					Attribute: fact.AttributeSignedGroup,
					Subject:   &fact.PeerSubject{Key: remotePubKey},
					Value:     svgFromFacts(t, facts.AliveFact(&remotePubKey, expires)),
				},
				properSource,
			},
			require.NoError,
			[]*ReceivedFact{
				rf(facts.AliveFact(&remotePubKey, expires)),
			},
		},
		{
			"valid various",
			fields{
				signer: localSigner,
			},
			args{
				&fact.Fact{
					Attribute: fact.AttributeSignedGroup,
					Subject:   &fact.PeerSubject{Key: remotePubKey},
					Value: svgFromFacts(t,
						facts.AliveFact(&remotePubKey, expires),
						facts.EndpointFactFull(properSource, &remotePubKey, expires),
					),
				},
				properSource,
			},
			require.NoError,
			[]*ReceivedFact{
				rf(facts.AliveFact(&remotePubKey, expires)),
				rf(facts.EndpointFactFull(properSource, &remotePubKey, expires)),
			},
		},
		{
			"corrupt",
			fields{
				signer: localSigner,
			},
			args{
				&fact.Fact{
					Attribute: fact.AttributeSignedGroup,
					Subject:   &fact.PeerSubject{Key: remotePubKey},
					Value:     corruptSGV(svgFromFacts(t, facts.AliveFact(&remotePubKey, expires))),
				},
				properSource,
			},
			// TODO: require a specific error
			require.Error,
			[]*ReceivedFact{},
		},
		{
			"wrong source",
			fields{
				signer: localSigner,
			},
			args{
				&fact.Fact{
					Attribute: fact.AttributeSignedGroup,
					Subject:   &fact.PeerSubject{Key: remotePubKey},
					Value:     svgFromFacts(t, facts.AliveFact(&remotePubKey, expires)),
				},
				improperSource,
			},
			// TODO: require a specific error
			require.Error,
			[]*ReceivedFact{},
		},
		{
			"truncated after signing",
			fields{
				signer: localSigner,
			},
			args{
				&fact.Fact{
					Attribute: fact.AttributeSignedGroup,
					Subject:   &fact.PeerSubject{Key: remotePubKey},
					Value:     shorten(svgFromFacts(t, facts.AliveFact(&remotePubKey, expires))),
				},
				properSource,
			},
			// TODO: require a specific error
			require.Error,
			[]*ReceivedFact{},
		},
		{
			"truncated before signing",
			fields{
				signer: localSigner,
			},
			args{
				&fact.Fact{
					Attribute: fact.AttributeSignedGroup,
					Subject:   &fact.PeerSubject{Key: remotePubKey},
					Value:     sign(shorten(svgFromFacts(t, facts.AliveFact(&remotePubKey, expires)))),
				},
				properSource,
			},
			// TODO: require a specific error
			require.Error,
			[]*ReceivedFact{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &LinkServer{
				config: &config.Server{},
				signer: tt.fields.signer,
			}
			// we make a channel with a huge buffer so that we can do this linearly
			// and not have goroutines and waits
			packetsChan := make(chan *ReceivedFact, 100)
			tt.assertion(t, s.processSignedGroup(tt.args.f, tt.args.source, now, packetsChan))
			close(packetsChan)
			packets := make([]*ReceivedFact, 0, 100)
			for p := range packetsChan {
				packets = append(packets, p)
			}
			assert.Equal(t, tt.wantPackets, packets)
		})
	}
}
