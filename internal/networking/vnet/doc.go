// Package vnet provides a virtual (as opposed to mocked) implementation of the
// abstracted UDP networking stack. Multiple virtual hosts can be created with
// network linkages between them to simulate packet flows.
package vnet

// notes on locking orders

// interface attach/detach: interface, network
// interface unregister: host lock released before doing interface detach
