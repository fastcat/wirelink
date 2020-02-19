package vnet

import (
	"net"
	"testing"

	"github.com/fastcat/wirelink/internal/testutils"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const wgPort = 51820

type smokeSetup struct {
	w                        *World
	internet, lan1, lan2     *Network
	host1, host2             *Host
	host1eth0, host1eth1     *PhysicalInterface
	host2eth0, host2eth1     *PhysicalInterface
	host1eth0ip, host2eth0ip net.IP
	host1wg0, host2wg0       *Tunnel
	host1wg0ip, host2wg0ip   net.IP
	host1wg0p1, host2wg0p1   *TunPeer
}

func initSmoke(t *testing.T) *smokeSetup {
	ss := &smokeSetup{
		w: NewWorld(),

		host1eth0ip: net.IPv4(100, 1, 1, 1),
		host2eth0ip: net.IPv4(100, 1, 1, 2),

		host1wg0ip: net.IPv4(10, 0, 0, 1),
		host2wg0ip: net.IPv4(10, 0, 0, 2),
	}

	ss.internet = ss.w.CreateNetwork("internet")
	ss.lan1 = ss.w.CreateNetwork("lan1")
	ss.lan2 = ss.w.CreateNetwork("lan2")

	ss.host1 = ss.w.CreateHost("host1")
	ss.host2 = ss.w.CreateHost("host2")

	ss.host1eth0 = ss.host1.AddPhy("eth0")
	ss.host1eth0.AddAddr(net.IPNet{
		IP:   ss.host1eth0ip,
		Mask: net.CIDRMask(24, 32),
	})
	ss.host1eth1 = ss.host1.AddPhy("eth1")
	ss.host1eth1.AddAddr(net.IPNet{
		IP:   net.IPv4(192, 168, 0, 1),
		Mask: net.CIDRMask(24, 32),
	})

	ss.host2eth0 = ss.host2.AddPhy("eth0")
	ss.host2eth0.AddAddr(net.IPNet{
		IP:   ss.host2eth0ip,
		Mask: net.CIDRMask(24, 32),
	})
	ss.host2eth1 = ss.host2.AddPhy("eth1")
	ss.host2eth1.AddAddr(net.IPNet{
		IP:   net.IPv4(192, 168, 0, 1),
		Mask: net.CIDRMask(24, 32),
	})

	ss.host2eth0.AttachToNetwork(ss.internet)
	ss.host1eth0.AttachToNetwork(ss.internet)
	ss.host1eth1.AttachToNetwork(ss.lan1)
	ss.host2eth1.AttachToNetwork(ss.lan2)

	_, host1pub := testutils.MustKeyPair(t)
	_, host2pub := testutils.MustKeyPair(t)

	ss.host1wg0 = ss.host1.AddTun("wg0")
	ss.host1wg0.AddAddr(net.IPNet{IP: ss.host1wg0ip, Mask: net.CIDRMask(24, 32)})
	ss.host2wg0 = ss.host2.AddTun("wg0")
	ss.host2wg0.AddAddr(net.IPNet{IP: ss.host2wg0ip, Mask: net.CIDRMask(24, 32)})
	ss.host1wg0p1 = ss.host1wg0.AddPeer(
		"peer:host2wg0",
		host2pub,
		&net.UDPAddr{IP: ss.host2eth0ip, Port: wgPort},
		[]net.IPNet{{IP: ss.host2wg0ip, Mask: net.CIDRMask(32, 32)}},
	)
	ss.host2wg0p1 = ss.host2wg0.AddPeer(
		"peer:host1wg0",
		host1pub,
		&net.UDPAddr{IP: ss.host1eth0ip, Port: wgPort},
		[]net.IPNet{{IP: ss.host1wg0ip, Mask: net.CIDRMask(32, 32)}},
	)

	ss.host1wg0.Listen(wgPort)
	ss.host2wg0.Listen(wgPort)

	return ss
}

func (s *smokeSetup) Close() {
	s.host1wg0.DetachFromNetwork()
	s.host2wg0.DetachFromNetwork()

	s.host1eth0.DetachFromNetwork()
	s.host2eth0.DetachFromNetwork()
	s.host1eth1.DetachFromNetwork()
	s.host2eth1.DetachFromNetwork()
}

func Test_Smoke_Direct(t *testing.T) {
	ss := initSmoke(t)
	defer ss.Close()

	// verify host-to-host communication over "internet"
	s1 := ss.host1.AddSocket(&net.UDPAddr{
		IP:   ss.host1eth0ip,
		Port: wgPort + 1,
	})
	s2 := ss.host2.AddSocket(&net.UDPAddr{
		IP:   ss.host2eth0ip,
		Port: wgPort + 1,
	})

	s1c := s1.Connect()
	defer s1c.Close()
	s2c := s2.Connect()
	defer s2c.Close()

	payload := testutils.MustRandBytes(t, make([]byte, 512))
	nSent, err := s1c.WriteToUDP(payload, &net.UDPAddr{IP: ss.host2eth0ip, Port: wgPort + 1})
	assert.NoError(t, err)
	assert.Equal(t, len(payload), nSent)

	readBuf := make([]byte, 1500)
	n, addr, err := s2c.ReadFromUDP(readBuf)
	assert.NoError(t, err)
	assert.Equal(t, len(payload), n)
	assert.Equal(t, payload, readBuf[:len(payload)])
	assert.Equal(t, &net.UDPAddr{IP: ss.host1eth0ip, Port: wgPort + 1}, addr)
}

func Test_Smoke_Tunnel(t *testing.T) {
	ss := initSmoke(t)
	defer ss.Close()

	// verify host-to-host communication over "internet"
	s1 := ss.host1wg0.AddSocket(&net.UDPAddr{
		IP:   ss.host1wg0ip,
		Port: wgPort + 1,
	})
	s2 := ss.host2wg0.AddSocket(&net.UDPAddr{
		IP:   ss.host2wg0ip,
		Port: wgPort + 1,
	})

	s1c := s1.Connect()
	defer s1c.Close()
	s2c := s2.Connect()
	defer s2c.Close()

	payload := testutils.MustRandBytes(t, make([]byte, 512))
	nSent, err := s1c.WriteToUDP(payload, &net.UDPAddr{IP: ss.host2wg0ip, Port: wgPort + 1})

	if assert.NoError(t, err) && assert.Equal(t, len(payload), nSent) {

		readBuf := make([]byte, 1500)
		n, addr, err := s2c.ReadFromUDP(readBuf)
		assert.NoError(t, err)
		assert.Equal(t, len(payload), n)
		assert.Equal(t, payload, readBuf[:len(payload)])
		assert.Equal(t, &net.UDPAddr{IP: ss.host1wg0ip, Port: wgPort + 1}, addr)
	}
}

func Test_Smoke_Wrap(t *testing.T) {
	ss := initSmoke(t)
	defer ss.Close()

	e1 := ss.host1.Wrap()
	defer e1.Close()
	e2 := ss.host2.Wrap()
	defer e2.Close()

	s1, err := e1.ListenUDP("udp6", &net.UDPAddr{
		IP:   ss.host1wg0ip,
		Port: wgPort + 1,
		Zone: ss.host1wg0.Name(),
	})
	require.NoError(t, err)
	defer s1.Close()

	s2, err := e2.ListenUDP("udp6", &net.UDPAddr{
		IP:   ss.host2wg0ip,
		Port: wgPort + 1,
		Zone: ss.host2wg0.Name(),
	})
	require.NoError(t, err)
	defer s2.Close()

	payload := testutils.MustRandBytes(t, make([]byte, 512))
	nSent, err := s1.WriteToUDP(payload, &net.UDPAddr{IP: ss.host2wg0ip, Port: wgPort + 1})

	if assert.NoError(t, err) && assert.Equal(t, len(payload), nSent) {

		readBuf := make([]byte, 1500)
		n, addr, err := s2.ReadFromUDP(readBuf)
		assert.NoError(t, err)
		assert.Equal(t, len(payload), n)
		assert.Equal(t, payload, readBuf[:len(payload)])
		assert.Equal(t, &net.UDPAddr{IP: ss.host1wg0ip, Port: wgPort + 1}, addr)
	}
}
