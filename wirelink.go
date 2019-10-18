package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"golang.zx2c4.com/wireguard/wgctrl"

	"github.com/fastcat/wirelink/server"
	"github.com/fastcat/wirelink/trust"
	"github.com/pkg/errors"
)

func main() {
	err := realMain()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		defer os.Exit(1)
	}
}

func realMain() error {
	wgc, err := wgctrl.New()
	if err != nil {
		return errors.Wrapf(err, "Unable to initialize wgctrl")
	}

	flags := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)

	const RouterFlag = "router"
	isRouter := flags.Bool(RouterFlag, false, "Is the local device a router (default is autodetected)")
	iface := "wg0"
	// TODO: make the env var formulation & parsing from flags more programatic
	// pull this one from the env before declaring the flag so the env var can be the flag "default"
	if ifaceEnv, ifaceEnvPresent := os.LookupEnv("WIRELINK_IFACE"); ifaceEnvPresent {
		iface = ifaceEnv
	}
	flags.StringVar(&iface, "iface", iface, "Interface on which to operate")
	isRouterSet := false
	// TODO: make the env var formulation & parsing from flags more programatic
	if routerEnv, routerEnvPresent := os.LookupEnv("WIRELINK_ROUTER"); routerEnvPresent {
		if routerEnvValue, err := strconv.ParseBool(routerEnv); err == nil {
			*isRouter = routerEnvValue
			isRouterSet = true
		} else {
			// TODO: printing usage before the error doesn't match how actual flag handling works,
			// but doesn't match our normal flags handling is done
			flags.Usage()
			return errors.Wrapf(err, "Invalid value \"%s\" for WIRELINK_ROUTER", routerEnv)
		}
	}
	err = flags.Parse(os.Args[1:])
	if err != nil {
		// TODO: this causes the error to be printed twice: once by flags and once by `main`
		return err
	}
	flags.Visit(func(f *flag.Flag) {
		if f.Name == RouterFlag {
			isRouterSet = true
		}
	})
	if !isRouterSet {
		// try to auto-detect router mode
		// if there are no other routers ... then we're probably a router
		// this is pretty weak, better would be to check if our IP is within some other peer's AllowedIPs
		dev, err := wgc.Device(iface)
		if err != nil {
			return errors.Wrapf(err, "Unable to open wireguard device for interface %s", iface)
		}

		otherRouters := false
		for _, p := range dev.Peers {
			if trust.IsRouter(&p) {
				otherRouters = true
				break
			}
		}

		if !otherRouters {
			*isRouter = true
		}
	}

	server, err := server.Create(wgc, iface, 0, *isRouter)
	if err != nil {
		return errors.Wrapf(err, "Unable to initialize server for interface %s", iface)
	}
	defer server.Close()

	routerString := "leaf"
	if *isRouter {
		routerString = "router"
	}
	fmt.Printf("Server running on {%s} [%v]:%v (%s)\n", iface, server.Address(), server.Port(), routerString)

	sigs := make(chan os.Signal, 5)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGUSR1)

	onStopped := server.OnStopped()

DONE:
	for {
		select {
		case sig := <-sigs:
			if sig == syscall.SIGUSR1 {
				server.RequestPrint()
			} else {
				fmt.Printf("Received signal %v, stopping\n", sig)
				// request stop in the background, we'll catch the channel message when it's complete
				go server.Stop()
			}
		case exitOk := <-onStopped:
			if !exitOk {
				fmt.Println("Server hit an error")
				defer os.Exit(1)
			} else {
				fmt.Println("Server stopped")
				server.RequestPrint()
			}
			break DONE
		}
	}

	// server.Close is handled by defer above
	return nil
}
