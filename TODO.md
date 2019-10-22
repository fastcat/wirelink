# TODO

## Endpoint Selection

* Prefer RFC1918 addresses that match a local interface over those that
  don't. TBD exactly what "prefer" means outside the first set of attempts.

## Router Detection

* Check the local interface's configured IP addresses against the peers'
  AllowedIPs. If nobody has an AllowedIP that overlaps our local IP, then we
  are probably a router.
  * This could change dynamically in theory as we receive AIP info from other
    peers, but that could only happen in practice if we have a p-t-p link to
    another non-router peer, otherwise there's no way for us to receive anything.

## Packaging

* Better pre/post inst/rm scripts for systemd service
* Release script
* ChangeLog generation

## Systemd Integration

* `sd_notify`

## Functionality

* Output verbosity levels
  * Esp. add debug/trace
* CLI/ENV args to control which interfaces to report for local endpoints
* Faster AIP config when receiving the first ping fact from a peer
  * Check received ping facts against `peerAlive`, if new force ending the current receive chunk?
* Don't activate AIP config until we think the peer will reciprocate
* Intelligent prioritizaiton of peer EPs to try
  * EPs that are on a local subnet, then EPs on the internet, then everything else?
  * Implement via LRU penalty?
* Option to de-configure at exit for leaves
  * i.e. reset wg config to as if every peer was unhealthy, only talk to routers
* Every now and then the handshakes don't refresh as often as they seem they should?
  * Causes peers to appear unhealthy and get deconfigured until reconnected
  * Shouldn't be fatal as routers can't be deconfigured, but will make for some packet loss
  * Happens even with persistent keepalive enabled between the peers
  * For now, handled with `HealthHysteresisBandiad`
  * For super-idle peers, is this related to the interaction between persistent keepalive
    and the peer alive fact interval?

## Security

* Drop privileges after startup
  * Close the netlink socket for local interface config when we don't need it any more
  * This is obstructed by Go's lack of support:
    https://github.com/golang/go/issues/1435
  * Worked around for now by having systemd units drop privs
* Improved trust models
* Sign facts with peer keys (protects against forgery from other processes on the same host)
  * This would obviate source port validation

## Fancy

* Use `pcap` or the like to detect when we are actually trying to talk to a peer
  * Use this to only do peer setup when we need it

### Reduced Chatter

* Send to non-routers less
  * Option to disable all p2p chatter except liveness, only send facts to router?
  * Need to be careful not to leave a peer in a dead setup (instead of resetting AllowedIPs)
* Tell routers who we want to talk to (a peer-valued fact)
  * Only tell leaves info about peers they want
* Multi-fact packets
  * How to find out path MTU to avoid fragmentation?

### Config

* Allow configuring trust in peers
* Allow configuring various parameters
  * `MaxChunk`
  * `ChunkPeriod`
  * `AlivePeriod`
  * `FactTTL`
  * listen port / offset
    * This one is a bit tricky as it needs to be consistent across the network for now
    * With signed facts, could have a fact for the fact port,
      though deciding among multiple values could get weird
