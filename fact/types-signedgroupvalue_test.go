package fact

import (
	"bytes"
	"io"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/stretchr/testify/assert"
)

type mockReader struct {
	buf *bytes.Buffer
}

func (mr *mockReader) Read(p []byte) (int, error) {
	if mr.buf == nil {
		panic("should not call this mock")
	}
	return mr.buf.Read(p)
}

var _ io.Reader = &mockReader{}

func byteVec(length int, offset int) []byte {
	ret := make([]byte, length)
	for i := 0; i < length; i++ {
		ret[i] = byte(i + offset)
	}
	return ret
}

func TestSignedGroupValue_DecodeFrom(t *testing.T) {
	type args struct {
		lengthHint int
		reader     io.Reader
	}
	tests := []struct {
		name      string
		args      args
		assertion assert.ErrorAssertionFunc
		result    *SignedGroupValue
	}{
		{
			"insufficient bytes for nonce",
			args{0, bytes.NewBuffer(make([]byte, chacha20poly1305.NonceSizeX-1))},
			func(t assert.TestingT, err error, msgAndArgs ...interface{}) bool {
				return assert.Error(t, err, msgAndArgs...) &&
					assert.ErrorContains(t, err, "Nonce")
			},
			nil,
		},
		{
			"insufficient bytes for tag",
			args{0, bytes.NewBuffer(make([]byte, chacha20poly1305.NonceSizeX+chacha20poly1305.Overhead-1))},
			func(t assert.TestingT, err error, msgAndArgs ...interface{}) bool {
				return assert.Error(t, err, msgAndArgs...) &&
					assert.ErrorContains(t, err, "Tag")
			},
			nil,
		},
		{
			"buffer success",
			args{0, bytes.NewBuffer(byteVec(chacha20poly1305.NonceSizeX+chacha20poly1305.Overhead+10, 0))},
			assert.NoError,
			func() *SignedGroupValue {
				ret := &SignedGroupValue{}
				copy(ret.Nonce[:], byteVec(chacha20poly1305.NonceSizeX, 0))
				copy(ret.Tag[:], byteVec(chacha20poly1305.Overhead, chacha20poly1305.NonceSizeX))
				ret.InnerBytes = byteVec(10, chacha20poly1305.NonceSizeX+chacha20poly1305.Overhead)
				return ret
			}(),
		},
		{
			"reader success",
			args{0, &mockReader{bytes.NewBuffer(byteVec(chacha20poly1305.NonceSizeX+chacha20poly1305.Overhead+10, 0))}},
			assert.NoError,
			func() *SignedGroupValue {
				ret := &SignedGroupValue{}
				copy(ret.Nonce[:], byteVec(chacha20poly1305.NonceSizeX, 0))
				copy(ret.Tag[:], byteVec(chacha20poly1305.Overhead, chacha20poly1305.NonceSizeX))
				ret.InnerBytes = byteVec(10, chacha20poly1305.NonceSizeX+chacha20poly1305.Overhead)
				return ret
			}(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sgv := &SignedGroupValue{}
			tt.assertion(t, sgv.DecodeFrom(tt.args.lengthHint, tt.args.reader))
			if tt.result != nil {
				assert.Equal(t, *tt.result, *sgv)
			}
		})
	}
}

func TestSignedGroupValue_ParseInner(t *testing.T) {
	type args struct {
		now time.Time
	}
	tests := []struct {
		name      string
		inner     []byte
		args      args
		wantRet   []*Fact
		assertion assert.ErrorAssertionFunc
	}{
		{
			"err on nested SGV",
			[]byte{byte(AttributeSignedGroup)},
			args{time.Now()},
			nil,
			func(t assert.TestingT, err error, msgAndArgs ...interface{}) bool {
				return assert.Error(t, err, msgAndArgs...) &&
					assert.ErrorContains(t, err, "nested")
			},
		},
		{
			"err on inner decode: legacy ping",
			[]byte{byte(AttributeUnknown)},
			args{time.Now()},
			nil,
			func(t assert.TestingT, err error, msgAndArgs ...interface{}) bool {
				return assert.Error(t, err, msgAndArgs...) &&
					assert.ErrorContains(t, err, "AttributeUnknown")
			},
		},
		{
			"err on inner decode: bogus",
			[]byte{0xff},
			args{time.Now()},
			nil,
			func(t assert.TestingT, err error, msgAndArgs ...interface{}) bool {
				return assert.Error(t, err, msgAndArgs...) &&
					assert.ErrorContains(t, err, "unrecognized")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sgv := &SignedGroupValue{
				InnerBytes: tt.inner,
			}
			gotRet, err := sgv.ParseInner(tt.args.now)
			tt.assertion(t, err)
			assert.Equal(t, tt.wantRet, gotRet)
		})
	}
}
