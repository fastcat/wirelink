# wirelink

## Concept

This is an experiment in implementing automatic link-locak ips for wireguard
peers, using that to automatically share information about available peers
and their endpoints, and using that finally to try to automatically give
peers direct connections when possible instead of routing through a central
"server".

## Overview

Peers produce a list of local "facts" based on information from the
wireguard device.  Facts have:

* A subject -- who is the fact about
* An attribute -- what attribute of the subject does the fact describe
* A value -- what is the value of that attribute
* A TTL -- for how long should this fact be considered valid

For now subjects are always a peer's public key.  Attributes are the peer's
allowed ip value(s) and their current endpoint if it seems live.

Peers periodically send all their locally known facts to all the other
peers.

Peers receive facts from other peers as they arrive, but filter them based
on a trust model.  For now trust is simple:

* Peers are trusted to provide information about themselves
* Peers that have an allowed ip value that implies they route packets are
  trusted to provide information about anyone

Received facts are removed as they expire based on the given TTL value.

## Connecting two peers

To connect two peers that aren't directly connected, each end
(independently) configures the remote peer in the local wireguard interface
with that peer's automatic link local address.  It then cycles through the
known endpoints and attempts to contact the peer.

If contact is successful, then the peers other allowed IPs are added and
traffic can start to flow directly.

TBD on how to define:

* Attempting to contact a peer
* Detecting successful contact
* When to detect contact is lost and deconfigure the direct connection

### Contact

A super simple method would be just trying to send an empty fact packet to
the peer and then monitoring to see if the last handshake for the peer
becomes live.

Better would be a ping/pong packet pair, but that gets complex to multiplex
with the rest of the fact receiving on the same port.  Adding a seecond port
is annoying.
