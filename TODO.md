# TODO

## Detection

* How do we detect if the local system is a router?

* How do we detect when a connection to a peer is operational enough that we
  should stop trying new endpoints?

  * Last handshake less than `RekeyAfterTime`?
  * Last handshake newer than we last observed?

* How do we detect when an endpoint isn't going to work and move on to the
  next one?

  * Last handshake hasn't changed in over `RekeyAfterTime`?
  * Last handshake hasn't changed in over `RekeyTimeout` +
    `KeepaliveTimeout`?

* How do we detect which endpoints we should try?

  * All of them? Filtering for RFC1918 addresses that match local
    interfaces may be a waste of time? At least save that for post MvP.

* How do we detect the order in which we should try endpoints?

  * Does it matter?

* How do we detect which endpoint we should try next, to ensure we try them
  all?

  * Remember a last attempted time for each one, prune that to only
    still-valid ones, sort?
