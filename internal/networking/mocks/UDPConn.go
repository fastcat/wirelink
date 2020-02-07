// Code generated by mockery v1.0.0. DO NOT EDIT.

package mocks

import (
	context "context"
	net "net"

	mock "github.com/stretchr/testify/mock"

	networking "github.com/fastcat/wirelink/internal/networking"

	time "time"
)

// UDPConn is an autogenerated mock type for the UDPConn type
type UDPConn struct {
	mock.Mock
}

// Close provides a mock function with given fields:
func (_m *UDPConn) Close() error {
	ret := _m.Called()

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ReadFromUDP provides a mock function with given fields: b
func (_m *UDPConn) ReadFromUDP(b []byte) (int, *net.UDPAddr, error) {
	ret := _m.Called(b)

	var r0 int
	if rf, ok := ret.Get(0).(func([]byte) int); ok {
		r0 = rf(b)
	} else {
		r0 = ret.Get(0).(int)
	}

	var r1 *net.UDPAddr
	if rf, ok := ret.Get(1).(func([]byte) *net.UDPAddr); ok {
		r1 = rf(b)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*net.UDPAddr)
		}
	}

	var r2 error
	if rf, ok := ret.Get(2).(func([]byte) error); ok {
		r2 = rf(b)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// ReadPackets provides a mock function with given fields: ctx, maxSize, output
func (_m *UDPConn) ReadPackets(ctx context.Context, maxSize int, output chan<- *networking.UDPPacket) error {
	ret := _m.Called(ctx, maxSize, output)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, int, chan<- *networking.UDPPacket) error); ok {
		r0 = rf(ctx, maxSize, output)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// SetReadDeadline provides a mock function with given fields: t
func (_m *UDPConn) SetReadDeadline(t time.Time) error {
	ret := _m.Called(t)

	var r0 error
	if rf, ok := ret.Get(0).(func(time.Time) error); ok {
		r0 = rf(t)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// SetWriteDeadline provides a mock function with given fields: t
func (_m *UDPConn) SetWriteDeadline(t time.Time) error {
	ret := _m.Called(t)

	var r0 error
	if rf, ok := ret.Get(0).(func(time.Time) error); ok {
		r0 = rf(t)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// WriteToUDP provides a mock function with given fields: p, addr
func (_m *UDPConn) WriteToUDP(p []byte, addr *net.UDPAddr) (int, error) {
	ret := _m.Called(p, addr)

	var r0 int
	if rf, ok := ret.Get(0).(func([]byte, *net.UDPAddr) int); ok {
		r0 = rf(p, addr)
	} else {
		r0 = ret.Get(0).(int)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func([]byte, *net.UDPAddr) error); ok {
		r1 = rf(p, addr)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}
