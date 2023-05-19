// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package router

import (
	"fmt"
	"net/netip"
	"sync/atomic"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/net/netmon"
	"tailscale.com/types/logger"
	"tailscale.com/util/multierr"
)

type freeBSDRouter struct {
	closed		atomic.Bool
	logf		func(fmt string, args ...any)
	tunname		string
	netMon		*netmon.Monitor
	addrs		map[netip.Prefix]bool
	routes		map[netip.Prefix]bool
	localRoutes	map[netip.Prefix]bool

	v6Available		bool
	v6NATAvailable	bool

	cmd commandRunner
}

func (r *freeBSDRouter) addRoute(cidr netip.Prefix) error {
	if !r.v6Available && cidr.Addr().Is6() {
		return nil
	}
	return r.cmd.run("route", "add", "-net", dashAddrFam(cidr.Addr()), normalizeCIDR(cidr), "-interface", r.tunname)
}

func (r *freeBSDRouter) delRoute(cidr netip.Prefix) error {
	if !r.v6Available && cidr.Addr().Is6() {
		return nil
	}
	return nil
}

func (r *freeBSDRouter) delRoutes() error {
	return nil
}

func normalizeCIDR(cidr netip.Prefix) string {
	return cidr.Masked().String()
}

func newUserspaceRouter(logf logger.Logf, tunDev tun.Device, netMon *netmon.Monitor) (Router, error) {
	tunname, err := tunDev.Name()
	if err != nil {
		return nil, err
	}

	cmd := osCommandRunner{
		ambientCapNetAdmin: false,
	}

	return newUserspaceRouterAdvanced(logf, tunname, netMon, cmd, true, true)
}

func newUserspaceRouterAdvanced(logf logger.Logf, tunname string, netMon *netmon.Monitor, cmd commandRunner, supportsV6, supportsV6NAT bool) (Router, error) {
	r := &freeBSDRouter{
		logf:			logf,
		tunname:		tunname,
		netMon:			netMon,

		v6Available:	supportsV6,
		v6NATAvailable:	supportsV6NAT,

		cmd:			cmd,
	}

	return r, nil
}

func (r *freeBSDRouter) upInterface() error {
	return r.cmd.run("ifconfig", r.tunname, "up")
}

func (r *freeBSDRouter) downInterface() error {
	return r.cmd.run("ifconfig", r.tunname, "down")
}

func addrFam(ip netip.Addr) string {
	if ip.Is6() {
		return "inet6"
	}
	return "inet"
}

func dashAddrFam(ip netip.Addr) string {
	if ip.Is6() {
		return "-inet6"
	}
	return "-inet"
}

func (r *freeBSDRouter) addAddress(addr netip.Prefix) error {
	if err := r.cmd.run("ifconfig", r.tunname, addrFam(addr.Addr()), addr.String(), "alias"); err != nil {
		return fmt.Errorf("adding address %q to tunnel interface: %w", addr, err)
	}
	return nil
}

func (r *freeBSDRouter) delAddress(addr netip.Prefix) error {
	if err := r.cmd.run("ifconfig", r.tunname, addrFam(addr.Addr()), addr.String(), "-alias"); err != nil {
		return fmt.Errorf("removing address %q to tunnel interface: %w", addr, err)
	}
	return nil
}

func (r *freeBSDRouter) Up() error {
	if err := r.upInterface(); err != nil {
		return fmt.Errorf("bringing interface %s up: %w", r.tunname, err)
	}
	return nil
}

func (r *freeBSDRouter) Close() error {
	r.closed.Store(true)
	if err := r.downInterface(); err != nil {
		return fmt.Errorf("bringing interface %s down: %w", r.tunname, err)
	}
	if err := r.delRoutes(); err != nil {
		return err
	}

	r.addrs = nil
	r.routes = nil
	r.localRoutes = nil

	return nil
}

func (r *freeBSDRouter) Set(cfg *Config) error {
	var errs []error
	if cfg == nil {
		cfg = &shutdownConfig
	}

	newAddrs, err := cidrDiff("addr", r.addrs, cfg.LocalAddrs, r.addAddress, r.delAddress, r.logf)
	if err != nil {
		errs = append(errs, err)
	}
	r.addrs = newAddrs

	newRoutes, err := cidrDiff("route", r.routes, cfg.Routes, r.addRoute, r.delRoute, r.logf)
	if err != nil {
		errs = append(errs, err)
	}
	r.routes = newRoutes

	return multierr.New(errs...)
}

// cidrDiff calls add and del as needed to make the set of prefixes in
// old and new match. Returns a map reflecting the actual new state
// (which may be somewhere in between old and new if some commands
// failed), and any error encountered while reconfiguring.
func cidrDiff(kind string, old map[netip.Prefix]bool, new []netip.Prefix, add, del func(netip.Prefix) error, logf logger.Logf) (map[netip.Prefix]bool, error) {
	newMap := make(map[netip.Prefix]bool, len(new))
	for _, cidr := range new {
		newMap[cidr] = true
	}

	// ret starts out as a copy of old, and updates as we
	// add/delete. That way we can always return it and have it be the
	// true state of what we've done so far.
	ret := make(map[netip.Prefix]bool, len(old))
	for cidr := range old {
		ret[cidr] = true
	}

	// We want to add before we delete, so that if there is no overlap, we don't
	// end up in a state where we have no addresses on an interface as that
	// results in other kernel entities (like routes) pointing to that interface
	// to also be deleted.
	var addFail []error
	for cidr := range newMap {
		if old[cidr] {
			continue
		}
		if err := add(cidr); err != nil {
			logf("%s add failed: %v", kind, err)
			addFail = append(addFail, err)
		} else {
			ret[cidr] = true
		}
	}

	if len(addFail) == 1 {
		return ret, addFail[0]
	}
	if len(addFail) > 0 {
		return ret, fmt.Errorf("%d add %s failures; first was: %w", len(addFail), kind, addFail[0])
	}

	var delFail []error
	for cidr := range old {
		if newMap[cidr] {
			continue
		}
		if err := del(cidr); err != nil {
			logf("%s del failed: %v", kind, err)
			delFail = append(delFail, err)
		} else {
			delete(ret, cidr)
		}
	}
	if len(delFail) == 1 {
		return ret, delFail[0]
	}
	if len(delFail) > 0 {
		return ret, fmt.Errorf("%d delete %s failures; first was: %w", len(delFail), kind, delFail[0])
	}

	return ret, nil
}

func cleanup(logf logger.Logf, interfaceName string) {
	// XXX-rcm 
}
