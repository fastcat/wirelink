package cmd

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/fastcat/wirelink/config"
	"github.com/fastcat/wirelink/internal/networking/vnet"
	"github.com/fastcat/wirelink/internal/testutils"
	"github.com/fastcat/wirelink/trust"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const wgPort = 51820

func Test_Cmd_VNet1(t *testing.T) {
	if testing.Short() {
		t.Skip("vnet acceptance tests are slow, skipping")
	}

	// setup our config path
	os.Setenv("WIREVLINK_CONFIG_PATH", testutils.SrcDirectory())
	defer os.Unsetenv("WIREVLINK_CONFIG_PATH")

	w := vnet.NewWorld()
	// the internet is 100/8
	internet := w.CreateNetwork("internet")
	// lan1 is 10.1.1/24
	lan1 := w.CreateNetwork("lan1")
	// lan2 is 10.2.2/24
	lan2 := w.CreateNetwork("lan2")
	// the wireguard network is 192.168.0/24

	// host 1 is the central server
	// it is connected to the internet and to lan1
	host1 := w.CreateHost("core")
	defer host1.Close()
	h1e0 := host1.AddPhy("eth0")
	h1e0.AddAddr(net.IPNet{IP: net.IPv4(100, 1, 1, 1), Mask: net.CIDRMask(24, 32)})
	h1e0.AttachToNetwork(internet)
	h1e1 := host1.AddPhy("eth1")
	h1e1.AddAddr(net.IPNet{IP: net.IPv4(10, 0, 0, 1), Mask: net.CIDRMask(24, 32)})
	h1e1.AttachToNetwork(lan1)
	h1w0 := host1.AddTun("wg0")
	h1w0.GenerateKeys()
	h1w0.AddAddr(net.IPNet{IP: net.IPv4(192, 168, 0, 1), Mask: net.CIDRMask(24, 32)})
	h1w0.Listen(wgPort)
	// don't add any peers, we'll do that with config

	// clients are roaming devices that are sometimes on lan1,
	// sometimes on lan2, sometimes maybe neither, initially nowhere
	addClient := func(i int) *vnet.Host {
		name := fmt.Sprintf("client%d", i)
		client := w.CreateHost(name)

		// client NICs are initially not connected to a network, though they are addressed for internet/lan1
		ce0 := client.AddPhy("eth0")
		ce0.AddAddr(net.IPNet{IP: net.IPv4(100, 1, 1, byte(1+i)), Mask: net.CIDRMask(24, 32)})
		ce1 := client.AddPhy("wl0")
		ce1.AddAddr(net.IPNet{IP: net.IPv4(10, 0, 0, byte(1+i)), Mask: net.CIDRMask(24, 32)})

		// we name client interfaces wg1 to make loading the test json easier
		cwg := client.AddTun("wg1")
		// test the other way of loading in keys
		priv, err := wgtypes.GeneratePrivateKey()
		require.NoError(t, err)
		cwg.UseKey(priv)
		cwgPriv, cwgPub := cwg.Keys()
		assert.Equal(t, priv, cwgPriv)
		assert.Equal(t, priv.PublicKey(), cwgPub)
		cwg.AddAddr(net.IPNet{IP: net.IPv4(192, 168, 0, byte(1+i)), Mask: net.CIDRMask(24, 32)})
		cwg.Listen(wgPort)

		return client
	}

	client1 := addClient(1)
	defer client1.Close()
	client2 := addClient(2)
	defer client2.Close()

	host1cmd := New([]string{"wirevlink", "--iface=wg0", "--router=true", "--debug"})
	client1cmd := New([]string{"wirevlink", "--iface=wg1", "--router=false", "--debug"})
	client2cmd := New([]string{"wirevlink", "--iface=wg1", "--router=false", "--debug"})

	require.NoError(t, host1cmd.Init(host1.Wrap()))
	require.NoError(t, client1cmd.Init(client1.Wrap()))
	require.NoError(t, client2cmd.Init(client2.Wrap()))

	// use shortened timing for the tests
	const factTTL = 6 * time.Second
	const chunkPeriod = 1 * time.Second
	for _, c := range []*WirelinkCmd{host1cmd, client1cmd, client2cmd} {
		c.Server.FactTTL = factTTL
		c.Server.ChunkPeriod = chunkPeriod
	}

	h1pub := h1w0.PublicKey()
	c1pub := client1.Interface("wg1").(*vnet.Tunnel).PublicKey()
	c2pub := client2.Interface("wg1").(*vnet.Tunnel).PublicKey()
	// hack in configs for peers
	host1cmd.Config.Peers[h1pub] = &config.Peer{
		Name:  host1.Name(),
		Trust: trust.Ptr(trust.Membership),
	}
	host1cmd.Config.Peers[c1pub] = &config.Peer{
		Name: client1.Name(),
	}
	host1cmd.Config.Peers[c2pub] = &config.Peer{
		Name: client2.Name(),
	}
	// TODO: name & explicitly configure client1 & client2
	client1cmd.Config.Peers[h1pub] = &config.Peer{
		Name:  host1.Name(),
		Trust: trust.Ptr(trust.Membership),
		Endpoints: []config.PeerEndpoint{{
			Host: "100.1.1.1",
			Port: wgPort,
		}},
	}
	client2cmd.Config.Peers[h1pub] = &config.Peer{
		Name:  host1.Name(),
		Trust: trust.Ptr(trust.Membership),
		Endpoints: []config.PeerEndpoint{{
			Host: "100.1.1.1",
			Port: wgPort,
		}},
	}

	// startTime := time.Now()
	eg := &errgroup.Group{}
	eg.Go(host1cmd.Run)
	eg.Go(client1cmd.Run)
	eg.Go(client2cmd.Run)

	time.Sleep(time.Second)
	host1cmd.Server.RequestPrint()
	client1cmd.Server.RequestPrint()
	client2cmd.Server.RequestPrint()

	// connect the clients to the internet after a delay
	clientConnectTime := time.Now()
	client1.Interface("eth0").(*vnet.PhysicalInterface).AttachToNetwork(internet)
	client2.Interface("eth0").(*vnet.PhysicalInterface).AttachToNetwork(internet)

	assertHealthy := func(h *vnet.Host, iface string, peer wgtypes.Key, after time.Time, msg string) {
		wg := h.Interface(iface).(*vnet.Tunnel)
		wgp := wg.Peers()
		ps := peer.String()
		if assert.Contains(t, wgp, ps, "%s: should know peer", msg) {
			p := wgp[ps]
			assert.NotNil(t, p.Endpoint(), "%s: should have an endpoint")
			if after != (time.Time{}) {
				assert.True(t, p.LastReceive().After(after), "%s: should have data from peer", msg)
			}
		}
	}

	assertNotKnows := func(h *vnet.Host, iface string, peer wgtypes.Key, msg string) {
		wg := h.Interface(iface).(*vnet.Tunnel)
		wgp := wg.Peers()
		ps := peer.String()
		assert.NotContains(t, wgp, ps, "%s: should not know peer", msg)
	}

	time.Sleep(chunkPeriod * 11 / 10)
	t.Log("Printing state 1: server should be connected to clients")
	host1cmd.Server.RequestPrint()
	client1cmd.Server.RequestPrint()
	client2cmd.Server.RequestPrint()
	assertHealthy(host1, "wg0", c1pub, clientConnectTime, "h knows c1")
	assertHealthy(host1, "wg0", c2pub, clientConnectTime, "h knows c2")
	assertHealthy(client1, "wg1", h1pub, clientConnectTime, "c1 knows h")
	assertHealthy(client2, "wg1", h1pub, clientConnectTime, "c2 knows h")

	time.Sleep(chunkPeriod * 21 / 10)
	t.Log("Printing state 2: clients should be connected to each other")
	// SIGUSR1 does the same thing as RequestPrint
	host1cmd.signals <- syscall.SIGUSR1
	client1cmd.signals <- syscall.SIGUSR1
	client2cmd.signals <- syscall.SIGUSR1
	assertHealthy(host1, "wg0", c1pub, clientConnectTime, "h knows c1")
	assertHealthy(host1, "wg0", c2pub, clientConnectTime, "h knows c2")
	assertHealthy(client1, "wg1", h1pub, clientConnectTime, "c1 knows h")
	assertHealthy(client2, "wg1", h1pub, clientConnectTime, "c2 knows h")
	assertHealthy(client1, "wg1", c2pub, clientConnectTime, "c1 knows c2")
	assertHealthy(client2, "wg1", c1pub, clientConnectTime, "c2 knows c1")

	// de-auth client2
	t.Logf("Removing client2 = %s", c2pub)
	host1.Interface("wg0").(*vnet.Tunnel).DelPeer(c2pub.String())
	// have to remove it from the config too else it'll keep getting broadcast,
	// and will get added back
	host1cmd.Server.MutateConfig(func(c *config.Server) {
		delete(host1cmd.Config.Peers, c2pub)
	})
	// coverage: add a bogus third client to client1
	// both of these should be removed
	_, badPub := testutils.MustKeyPair(t)
	t.Logf("Adding bogus peer %s", badPub)
	client1.Interface("wg1").(*vnet.Tunnel).AddPeer(
		"badpeer",
		badPub,
		testutils.RandUDP4Addr(t),
		[]net.IPNet{testutils.RandIPNet(t, net.IPv4len, []byte{192, 168, 1}, nil, 24)},
	)
	time.Sleep(factTTL + chunkPeriod*11/10)
	t.Log("Printing state 3: bad/removed clients should be deleted")
	// SIGUSR1 does the same thing as RequestPrint
	host1cmd.signals <- syscall.SIGUSR1
	client1cmd.signals <- syscall.SIGUSR1
	client2cmd.signals <- syscall.SIGUSR1
	// assert client2 and badpub have been evicted
	assertHealthy(host1, "wg0", c1pub, clientConnectTime, "h knows c1")
	assertNotKnows(host1, "wg0", c2pub, "h removed c2")
	assertHealthy(client1, "wg1", h1pub, clientConnectTime, "c1 knows h")
	// TODO: what should c2 think about h1 here?
	assertNotKnows(client1, "wg1", c2pub, "c1 removed c2")
	// tODO: what should c2 think about c1 here?
	assertNotKnows(client1, "wg1", badPub, "c1 removed badpub")

	t.Log("Stopping servers")
	// could call RequestStop on each, but testing signal handling is handy
	host1cmd.signals <- syscall.SIGINT
	client1cmd.signals <- syscall.SIGINT
	client2cmd.signals <- syscall.SIGINT

	err := eg.Wait()
	assert.NoError(t, err)

	// just to silence variable usage
	assert.NotNil(t, lan2)
}
