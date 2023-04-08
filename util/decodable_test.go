package util

import (
	"bytes"
	"errors"
	"io"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type unmarshal struct {
	data []byte
	err  error
}

func (u *unmarshal) UnmarshalBinary(data []byte) error {
	u.data = data
	return u.err
}

// wrapper around a bytes buffer to prevent identification as one
type alternateBuffer struct {
	bytes.Buffer
	err error
}

func (a *alternateBuffer) Read(p []byte) (int, error) {
	if a.err != nil {
		return 0, a.err
	}
	return a.Buffer.Read(p)
}

var seedOffset int64

func bytesFromSeed(seed int64, len int) []byte {
	if seedOffset == 0 {
		seedOffset = rand.Int63()
	}
	ret := make([]byte, len)
	r := rand.New(rand.NewSource(seed + seedOffset))
	// rand.Read never fails, no need to check returns
	r.Read(ret)
	return ret
}

func bufFromSeed(seed int64, len int) *bytes.Buffer {
	return bytes.NewBuffer(bytesFromSeed(seed, len))
}

func altFromSeed(seed int64, len int) *alternateBuffer {
	return &alternateBuffer{
		Buffer: *bufFromSeed(seed, len),
	}
}

func errFromSeed(seed int64, len int) *alternateBuffer {
	return &alternateBuffer{
		Buffer: *bufFromSeed(seed, len),
		err:    errors.New("Mock buffer read error"),
	}
}

func TestDecodeFrom(t *testing.T) {
	readLen := 16 + rand.Intn(16)
	type args struct {
		value   *unmarshal
		readLen int
		reader  io.Reader
	}
	tests := []struct {
		name      string
		args      args
		wantValue []byte
		wantErr   bool
	}{
		{
			"simple read from byte buffer",
			args{
				value:   &unmarshal{},
				readLen: readLen,
				reader:  bufFromSeed(1, readLen),
			},
			bytesFromSeed(1, readLen),
			false,
		},
		{
			"simple read from reader",
			args{
				value:   &unmarshal{},
				readLen: readLen,
				reader:  altFromSeed(2, readLen),
			},
			bytesFromSeed(2, readLen),
			false,
		},
		{
			"read error",
			args{
				value:   &unmarshal{},
				readLen: readLen,
				reader:  errFromSeed(3, readLen),
			},
			nil,
			true,
		},
		{
			"short read",
			args{
				value:   &unmarshal{},
				readLen: readLen,
				reader:  bufFromSeed(4, readLen-1),
			},
			nil,
			true,
		},
		{
			"unmarshal error",
			args{
				value:   &unmarshal{nil, errors.New("Mock fail unmarshal")},
				readLen: readLen,
				reader:  bufFromSeed(5, readLen),
			},
			bytesFromSeed(5, readLen),
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := DecodeFrom(tt.args.value, tt.args.readLen, tt.args.reader)
			if tt.wantErr {
				require.NotNil(t, err, "DecodeFrom() error")
			} else {
				require.Nil(t, err, "DecodeFrom() error")
			}
			assert.Equal(t, tt.args.value.data, tt.wantValue)
		})
	}
}
