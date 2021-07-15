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
	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/internal/networking/vnet"
	"github.com/fastcat/wirelink/internal/testutils"
	"github.com/fastcat/wirelink/log"
	"github.com/fastcat/wirelink/trust"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const wgPort = 51820

func Test_Cmd_VNet1(t *testing.T) {
	// use a 100ms time quantum for this test so we can run things on shorter timers
	fact.ScaleExpirationQuantumForTests(20) // 50ms quantum
	quantum := time.Second / 20
	defer fact.ScaleExpirationQuantumForTests(1)

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
	_, h1pub := h1w0.GenerateKeys()
	h1w0.AddAddr(net.IPNet{IP: net.IPv4(192, 168, 0, 1), Mask: net.CIDRMask(24, 32)})
	h1w0.Listen(wgPort)
	// don't add any peers, we'll do that with config
	log.Debug("host1 is %s", h1pub)

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

		log.Debug("client%d is %s", i, cwgPub)

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
	// in order for things to work properly, we need the chunk period, the fact ttl,
	// and the expiration quantum to all be integer multiples with quantum < period < ttl
	chunkPeriod := 3 * quantum // 150ms
	factTTL := 3 * chunkPeriod // 450ms

	for _, c := range []*WirelinkCmd{host1cmd, client1cmd, client2cmd} {
		c.Server.FactTTL = factTTL
		c.Server.ChunkPeriod = chunkPeriod
		// send alive packets aggressively so our connectivity assertions are simple
		c.Server.AlivePeriod = chunkPeriod / 2
	}

	c1pub := client1.Interface("wg1").(*vnet.Tunnel).PublicKey()
	c2pub := client2.Interface("wg1").(*vnet.Tunnel).PublicKey()
	// hack in configs for peers
	host1cmd.Config.Peers[h1pub] = &config.Peer{
		Name:  host1.Name() + "@self",
		Trust: trust.Ptr(trust.Membership),
	}
	host1cmd.Config.Peers[c1pub] = &config.Peer{
		Name:       client1.Name() + "@" + host1.Name(),
		AllowedIPs: []net.IPNet{{IP: net.IPv4(192, 168, 0, 2), Mask: net.CIDRMask(32, 32)}},
	}
	host1cmd.Config.Peers[c2pub] = &config.Peer{
		Name:       client2.Name() + "@" + host1.Name(),
		AllowedIPs: []net.IPNet{{IP: net.IPv4(192, 168, 0, 3), Mask: net.CIDRMask(32, 32)}},
	}
	client1cmd.Config.Peers[h1pub] = &config.Peer{
		Name:  host1.Name() + "@" + client1.Name(),
		Trust: trust.Ptr(trust.Membership),
		Endpoints: []config.PeerEndpoint{{
			Host: "100.1.1.1",
			Port: wgPort,
		}},
	}
	client1cmd.Config.Peers[c1pub] = &config.Peer{
		Name: client1.Name() + "@self",
	}
	client2cmd.Config.Peers[h1pub] = &config.Peer{
		Name:  host1.Name() + "@" + client2.Name(),
		Trust: trust.Ptr(trust.Membership),
		Endpoints: []config.PeerEndpoint{{
			Host: "100.1.1.1",
			Port: wgPort,
		}},
	}
	client2cmd.Config.Peers[c2pub] = &config.Peer{
		Name: client2.Name() + "@self",
	}

	eg := &errgroup.Group{}
	eg.Go(host1cmd.Run)
	eg.Go(client1cmd.Run)
	eg.Go(client2cmd.Run)

	printWithSignals := false
	printAll := func(msg string) {
		log.Debug(msg)
		for _, c := range []*WirelinkCmd{host1cmd, client1cmd, client2cmd} {
			if printWithSignals {
				c.sendPrintRequestSignal()
			} else {
				c.Server.RequestPrint()
			}
			printWithSignals = !printWithSignals
		}
	}

	time.Sleep(chunkPeriod / 2)
	printAll("Printing state 0: startup")

	// connect the clients to the internet after a delay
	client1.Interface("eth0").(*vnet.PhysicalInterface).AttachToNetwork(internet)
	client2.Interface("eth0").(*vnet.PhysicalInterface).AttachToNetwork(internet)

	assertHealthy := func(h *vnet.Host, iface string, peer wgtypes.Key, aip bool, msg string) {
		wg := h.Interface(iface).(*vnet.Tunnel)
		wgp := wg.Peers()
		ps := peer.String()
		if assert.Contains(t, wgp, ps, "%s: should know peer", msg) {
			p := wgp[ps]
			assert.NotNil(t, p.Endpoint(), "%s: should have an endpoint", msg)
			// can't use greater/less with durations nicely
			receiveAge := time.Since(p.LastReceive())
			require.True(t, receiveAge <= chunkPeriod, "%s: should have recent data from peer: %v > %v", msg, receiveAge, chunkPeriod)
			if aip {
				pa := p.Addrs()
				assert.Condition(t, func() bool {
					for _, a := range pa {
						if a.IP.To4() != nil {
							return true
						}
					}
					return false
				}, "%s: should have an AIP added", msg)
			}
		}
	}
	assertUnhealthy := func(h *vnet.Host, iface string, peer wgtypes.Key, aip *bool, msg string) {
		wg := h.Interface(iface).(*vnet.Tunnel)
		wgp := wg.Peers()
		ps := peer.String()
		if assert.Contains(t, wgp, ps, "%s: should know peer", msg) {
			p := wgp[ps]
			assert.NotNil(t, p.Endpoint(), "%s: should have an endpoint")
			// can't use greater/less with durations nicely
			receiveAge := time.Since(p.LastReceive())
			assert.True(t, receiveAge > chunkPeriod, "%s: should not have recent data from peer", msg)
			pa := p.Addrs()
			if aip != nil {
				assert.Condition(t, func() bool {
					for _, a := range pa {
						if a.IP.To4() != nil {
							return *aip
						}
					}
					return !*aip
				}, "%s: AIP presence should be %v", msg, aip)
			}
		}
	}

	assertNotKnows := func(h *vnet.Host, iface string, peer wgtypes.Key, msg string) {
		wg := h.Interface(iface).(*vnet.Tunnel)
		wgp := wg.Peers()
		ps := peer.String()
		assert.NotContains(t, wgp, ps, "%s: should not know peer", msg)
	}

	// clients connected at 0.5c
	// they will ping server at 1c
	// server may not notice them and ping back until 2c
	// server likely has AIPs for clients live here, but not vice versa
	time.Sleep(chunkPeriod * 2) // after 2c
	printAll("Printing state 1a: host/client handshakes")
	assertHealthy(host1, "wg0", c1pub, false, "1a: h knows c1")
	assertHealthy(host1, "wg0", c2pub, false, "1a: h knows c2")
	assertHealthy(client1, "wg1", h1pub, false, "1a: c1 knows h")
	assertHealthy(client2, "wg1", h1pub, false, "1a: c2 knows h")

	// one more cycle after pings, AIPs should be alive in both directions
	// server should be sending data about the peers out to each other now, but
	// peers may not have everything online yet
	time.Sleep(chunkPeriod) // after 3c
	printAll("Printing state 1b: host/client AIPs")
	assertHealthy(host1, "wg0", c1pub, true, "1b: h knows c1")
	assertHealthy(host1, "wg0", c2pub, true, "1b: h knows c2")
	assertHealthy(client1, "wg1", h1pub, true, "1b: c1 knows h")
	assertHealthy(client2, "wg1", h1pub, true, "1b: c2 knows h")
	// assertHealthy(client1, "wg1", c2pub, false, "1b: c1 knows c2")
	// assertHealthy(client2, "wg1", c1pub, false, "1b: c2 knows c1")

	// it may take two more cycles for clients to get info about each other from
	// the server, they definitely should know each other by then and may have
	// AIPs, but also may not due to race conditions
	time.Sleep(2 * chunkPeriod) // after 5c
	printAll("Printing state 2a: host/client AIPs and client/client handshakes")
	assertHealthy(host1, "wg0", c1pub, true, "2a: h knows c1")
	assertHealthy(host1, "wg0", c2pub, true, "2a: h knows c2")
	assertHealthy(client1, "wg1", h1pub, true, "2a: c1 knows h")
	assertHealthy(client2, "wg1", h1pub, true, "2a: c2 knows h")
	assertHealthy(client1, "wg1", c2pub, false, "2a: c1 knows c2")
	assertHealthy(client2, "wg1", c1pub, false, "2a: c2 knows c1")

	// one more cycle should definitely have AIPs
	time.Sleep(chunkPeriod) // after 6c
	printAll("Printing state 2b: full AIPs")
	assertHealthy(host1, "wg0", c1pub, true, "2b: h knows c1")
	assertHealthy(host1, "wg0", c2pub, true, "2b: h knows c2")
	assertHealthy(client1, "wg1", h1pub, true, "2b: c1 knows h")
	assertHealthy(client2, "wg1", h1pub, true, "2b: c2 knows h")
	assertHealthy(client1, "wg1", c2pub, true, "2b: c1 knows c2")
	assertHealthy(client2, "wg1", c1pub, true, "2b: c2 knows c1")

	// TODO: instead of de-authing client2, simply take it offline and make sure
	// it is removed from client1

	// de-auth client2
	log.Debug("Removing client2 = %s", c2pub)
	host1.Interface("wg0").(*vnet.Tunnel).DelPeer(c2pub.String())
	// have to remove it from the config too else it'll keep getting broadcast,
	// and will get added back
	host1cmd.Server.MutateConfig(func(c *config.Server) {
		delete(host1cmd.Config.Peers, c2pub)
	})
	// coverage: add a bogus third client to client1
	// both of these should be removed
	_, badPub := testutils.MustKeyPair(t)
	log.Debug("Adding bogus peer %s", badPub)
	client1.Interface("wg1").(*vnet.Tunnel).AddPeer("badpeer", badPub, nil, nil)

	time.Sleep(factTTL*2 + chunkPeriod) // ...?
	printAll("Printing state 3: delete clients")
	// assert client2 and badpub have been evicted
	assertHealthy(host1, "wg0", c1pub, true, "3: h knows c1")
	assertNotKnows(host1, "wg0", c2pub, "3: h removed c2")
	assertHealthy(client1, "wg1", h1pub, true, "3: c1 knows h")
	// c2 should no longer have an alive connection to h,
	// and thus should have forgotten its AIPs, but not removed the static trust source.
	// however, because h is healthy (HandshakeValidity is not adjusted for the test timing here),
	// it may or may not have reconfigured it to remove the AIPs from the device
	// which way it goes is a race condition of precise results from time.Now()
	// due to this expiring at exactly the same time, so we ignore the results in this case
	// in the real world, eventually the handshake would expire and h@c2 would be
	// reset to LL-only mode
	assertUnhealthy(client2, "wg1", h1pub, nil, "3: c2 blocked from h")
	assertNotKnows(client1, "wg1", c2pub, "3: c1 removed c2")
	// c2 no longer gets data, so it shouldn't think it's safe to delete peers,
	// but it should reset them to LL-only
	// same HandshakeValidity notes apply here
	assertUnhealthy(client2, "wg1", c1pub, boolPtr(true), "3: c2 retains c1")
	assertNotKnows(client1, "wg1", badPub, "3: c1 removed badpub")
	assertNotKnows(host1, "wg0", badPub, "3: h never knows badpub")
	assertNotKnows(client2, "wg1", badPub, "3: c2 never knows badpub")

	// make sure the prints above came through
	time.Sleep(100 * time.Millisecond)
	log.Debug("Stopping servers")
	// could call RequestStop on each, but testing signal handling is handy
	host1cmd.signals <- syscall.SIGINT
	client1cmd.signals <- syscall.SIGINT
	client2cmd.signals <- syscall.SIGINT

	err := eg.Wait()
	assert.NoError(t, err)

	// just to silence variable usage
	assert.NotNil(t, lan2)
}

func boolPtr(value bool) *bool {
	return &value
}
