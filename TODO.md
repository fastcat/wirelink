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

* Don't activate AIP config until we think the peer will reciprocate
* Intelligent prioritization of peer EPs to try
  * EPs that are on a local subnet, then EPs on the internet, then everything else?
  * Implement via LRU penalty?
* Option to de-configure at exit for leaves
  * i.e. reset wg config to as if every peer was unhealthy, only talk to routers
* Every now and then the handshakes don't refresh as often as they seem they should?
  * Causes peers to appear unhealthy and get deconfigured until reconnected
  * Shouldn't be fatal as routers can't be deconfigured, but will make for some packet loss
  * Happens even with persistent keepalive enabled between the peers
  * For now, handled with `HealthHysteresisBandaid`
  * For super-idle peers, is this related to the interaction between persistent keepalive
    and the peer alive fact interval?
* Only do lookups for static facts when we _really_ need them
  * Current only does it when the peer isn't healthy & alive
  * E.g. only do it if we have run through all the currently known endpoints
    without success, then do one lookup round and add all those to the local state
  * Even even better, only do lookups if we have no connections to any peers,
    or maybe just any routers. If we have a peer connection, we _should_ be able
    to get info from that peer, unless we've become an isolated island. If we
    have connections to a router, we _definitely_ should have network visibility.
* Fix problems with peer deletion due to not having detected trust source went offline
  * The problem is that the last facts can expire before we realize the trust source is gone
  * Probably need hysteresis on the delete decision: don't delete the peer until we've thought it was
    deletable for a full fact TTL
* Don't just remove peers based on trust, but remove AIPs too
  * Allow the trust source to change a peer's AIP(s) without having to remove
    the peer, wait for that to go through, and then re-add it with the new value(s)

## Security

* Drop privileges after startup
  * Close the netlink socket for local interface config when we don't need it any more
  * This is obstructed by Go's lack of support:
    [golang/go#1435](https://github.com/golang/go/issues/1435)
  * Worked around for now by having systemd units drop privileges
* Improved trust models

## Fancy

* Use packet capture to detect when we are actually trying to talk to a peer
  * Use this to only do peer setup when we need it

### Chatter Management

* Tell routers who we want to talk to (a peer-valued fact)
  * Only tell leaves info about peers they want

### Config

* Allow configuring various parameters
  * `MaxChunk`
  * `ChunkPeriod`
  * `AlivePeriod`
  * `FactTTL`
  * listen port / offset
    * This one is a bit tricky as it needs to be consistent across the network for now
    * With signed facts, could have a fact for the fact port,
      though deciding among multiple values could get weird
* Allow configuring allowed ips in config file
