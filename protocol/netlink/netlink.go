// Copyright (C) 2017 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package netlink

import (
	"fmt"
	"net"
	"sync"
	"syscall"

	log "github.com/Sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"

	"github.com/osrg/goplane/config"
	proto "github.com/osrg/goplane/protocol"
)

type NetlinkRouteEntry struct {
	route *netlink.Route
}

func (e *NetlinkRouteEntry) Match() proto.Match {
	return &proto.LPMatch{
		Prefix: e.route.Dst,
	}
}

func (e *NetlinkRouteEntry) Action() proto.Action {
	if len(e.route.MultiPath) == 0 {
		return &proto.ViaAction{
			Nexthops: []*proto.NexthopInfo{
				&proto.NexthopInfo{
					Nexthop:   e.route.Gw,
					LinkIndex: e.route.LinkIndex,
				},
			},
		}
	}
	nhs := make([]*proto.NexthopInfo, 0, len(e.route.MultiPath))
	for _, m := range e.route.MultiPath {
		nhs = append(nhs, &proto.NexthopInfo{
			Nexthop:   m.Gw,
			LinkIndex: m.LinkIndex,
		})
	}
	return &proto.ViaAction{
		Nexthops: nhs,
	}
}

type L2VPNEntry struct {
	vrf *config.VirtualNetwork
	mac net.HardwareAddr
	ip  net.IP
	nh  net.IP
}

func (e *L2VPNEntry) Match() proto.Match {
	return &proto.L2VPNMatch{
		VRF: *e.vrf,
		MAC: e.mac,
		IP:  e.ip,
	}
}

func (e *L2VPNEntry) Action() proto.Action {
	return &proto.ViaAction{
		Nexthops: []*proto.NexthopInfo{
			&proto.NexthopInfo{
				Nexthop: e.nh,
			},
		},
	}
}

func newL2VPNEntry(vrf *config.VirtualNetwork, mac net.HardwareAddr, ip, nh net.IP) *L2VPNEntry {
	return &L2VPNEntry{
		vrf: vrf,
		mac: mac,
		ip:  ip,
		nh:  nh,
	}
}

type NetlinkProtocol struct {
	vnMap    map[string]*VirtualNetwork
	m        sync.RWMutex
	routerID net.IP
}

func NewNetlinkProtocol() *NetlinkProtocol {
	p := &NetlinkProtocol{
		vnMap: make(map[string]*VirtualNetwork),
	}
	return p
}

func (p *NetlinkProtocol) SetRouterID(id net.IP) error {
	if p.routerID == nil {
		p.routerID = id

		lo, err := netlink.LinkByName("lo")
		if err != nil {
			return fmt.Errorf("failed to get lo")
		}

		addrList, err := netlink.AddrList(lo, netlink.FAMILY_ALL)
		if err != nil {
			return fmt.Errorf("failed to get addr list of lo")
		}

		addr, err := netlink.ParseAddr(p.routerID.String() + "/32")
		if err != nil {
			return fmt.Errorf("failed to parse addr: %s", p.routerID)
		}

		exist := false
		for _, a := range addrList {
			if a.Equal(*addr) {
				exist = true
			}
		}

		if !exist {
			log.Debugf("add route to lo")
			addr.Scope = 254
			err = netlink.AddrAdd(lo, addr)
			if err != nil {
				return fmt.Errorf("failed to add addr %s to lo", addr)
			}
		}
	}
	return nil
}

func (p *NetlinkProtocol) Type() proto.ProtocolType {
	return proto.PROTO_NETLINK
}

func (p *NetlinkProtocol) getNexthop(e proto.Entry) ([]*netlink.NexthopInfo, error) {
	var flags int
	d := e.Match().(*proto.LPMatch)
	v := e.Action().(*proto.ViaAction)
	nhs := make([]*netlink.NexthopInfo, 0, len(v.Nexthops))
	for _, nh := range v.Nexthops {
		gw := nh.Nexthop
		if (d.Prefix.IP.To4() != nil) && (gw.To4() != nil) {
			nhs = append(nhs, &netlink.NexthopInfo{
				Gw:    gw,
				Flags: flags,
			})
			continue
		}
		list, err := netlink.NeighList(0, netlink.FAMILY_V6)
		if err != nil {
			return nil, fmt.Errorf("failed to get neigh list: %s", err)
		}
		var neigh *netlink.Neigh
		for _, n := range list {
			if n.IP.Equal(nh.Nexthop) {
				neigh = &n
				break
			}
		}
		if neigh == nil {
			return nil, fmt.Errorf("no neighbor info for %s", d.Prefix.String())
		}
		list, err = netlink.NeighList(neigh.LinkIndex, netlink.FAMILY_V4)
		if err != nil {
			return nil, fmt.Errorf("failed to get neigh list: %s", err)
		}
		flags = int(netlink.FLAG_ONLINK)
		for _, n := range list {
			if n.HardwareAddr.String() == neigh.HardwareAddr.String() {
				nhs = append(nhs, &netlink.NexthopInfo{
					LinkIndex: n.LinkIndex,
					Gw:        n.IP.To4(),
					Flags:     flags,
				})
				goto NEXT
			}
		}
		gw = net.IPv4(169, 254, 0, 1)
		err = netlink.NeighAdd(&netlink.Neigh{
			LinkIndex:    neigh.LinkIndex,
			State:        netlink.NUD_PERMANENT,
			IP:           gw,
			HardwareAddr: neigh.HardwareAddr,
		})
		if err != nil {
			return nil, fmt.Errorf("neigh add: %s", err)
		}
		nhs = append(nhs, &netlink.NexthopInfo{
			LinkIndex: neigh.LinkIndex,
			Gw:        gw,
			Flags:     flags,
		})
	NEXT:
	}
	return nhs, nil
}

func (p *NetlinkProtocol) modLPEntry(e proto.Entry, del bool) error {
	if e.Action().Type() != proto.ACTION_VIA {
		return fmt.Errorf("unsupported action type: %d", e.Action().Type())
	}
	nhs, err := p.getNexthop(e)
	if err != nil {
		return err
	}
	if len(nhs) == 0 {
		return nil
	}
	route := &netlink.Route{
		Src:       p.routerID,
		Dst:       e.Match().(*proto.LPMatch).Prefix,
		MultiPath: nhs,
		Protocol:  RTPROT_GOPLANE,
	}
	log.Info("route: %s", route)
	if del {
		return netlink.RouteDel(route)
	}
	return netlink.RouteReplace(route)
}

func (p *NetlinkProtocol) modL2VPNEntry(e proto.Entry, del bool) error {
	p.m.RLock()
	defer p.m.RUnlock()
	m := e.Match().(*proto.L2VPNMatch)
	if vn, y := p.vnMap[m.VRF.RD]; !y {
		return fmt.Errorf("vrf %s not found", m.VRF)
	} else {
		return vn.ModFDB(e, del)
	}
}

func (p *NetlinkProtocol) modL2VPNMcastEntry(e proto.Entry, del bool) error {
	p.m.RLock()
	defer p.m.RUnlock()
	m := e.Match().(*proto.L2VPNMcastMatch)
	if vn, y := p.vnMap[m.VRF.RD]; !y {
		return fmt.Errorf("vrf %s not found", m.VRF)
	} else {
		return vn.ModConnMap(e, del)
	}
}

func (p *NetlinkProtocol) AddEntry(e proto.Entry) error {
	switch e.Match().Type() {
	case proto.MATCH_L2VPN:
		return p.modL2VPNEntry(e, false)
	case proto.MATCH_L2VPN_MCAST:
		return p.modL2VPNMcastEntry(e, false)
	case proto.MATCH_LP:
		return p.modLPEntry(e, false)
	default:
		return nil
	}
}

func (p *NetlinkProtocol) DeleteEntry(e proto.Entry) error {
	switch e.Match().Type() {
	case proto.MATCH_L2VPN:
		return p.modL2VPNEntry(e, true)
	case proto.MATCH_L2VPN_MCAST:
		return p.modL2VPNMcastEntry(e, true)
	case proto.MATCH_LP:
		return p.modLPEntry(e, true)
	default:
		return nil
	}
}

func (p *NetlinkProtocol) AddVirtualNetwork(routerID string, c config.VirtualNetwork) error {
	p.m.Lock()
	defer p.m.Unlock()
	v := NewVirtualNetwork(routerID, c)
	p.vnMap[c.RD] = v
	go v.Serve()
	return nil
}

func (p *NetlinkProtocol) DeleteVirtualNetwork(c config.VirtualNetwork) error {
	p.m.Lock()
	defer p.m.Unlock()
	v := p.vnMap[c.RD]
	v.Stop()
	delete(p.vnMap, v.config.RD)
	return nil
}

func (p *NetlinkProtocol) getVRFByLinkIndex(index int) *config.VirtualNetwork {
	p.m.RLock()
	defer p.m.RUnlock()
	for _, v := range p.vnMap {
		for _, i := range v.config.MemberInterfaces {
			link, _ := netlink.LinkByName(i)
			if link.Attrs().Index == index {
				return &v.config
			}
		}
	}
	return nil
}

type NetlinkEntryWatcher struct {
	socket  *nl.NetlinkSocket
	p       *NetlinkProtocol
	neighCh chan []syscall.NetlinkMessage
	linkCh  chan netlink.LinkUpdate
	routeCh chan netlink.RouteUpdate
	closeCh chan struct{}
}

func (w *NetlinkEntryWatcher) Recv() ([]proto.EntryEvent, error) {
	for {
		select {
		case msgs := <-w.neighCh:
			events := make([]proto.EntryEvent, 0, len(msgs))
			for _, msg := range msgs {
				t := RTM_TYPE(msg.Header.Type)
				withdraw := false
				switch t {
				case RTM_DELNEIGH:
					withdraw = true
					fallthrough
				case RTM_NEWNEIGH:
					n, _ := netlink.NeighDeserialize(msg.Data)
					if vrf := w.p.getVRFByLinkIndex(n.LinkIndex); vrf != nil {
						events = append(events, proto.EntryEvent{
							Entry: newL2VPNEntry(vrf, n.HardwareAddr, n.IP, nil),
							IsDel: withdraw,
							From:  proto.PROTO_NETLINK,
						})
					}
				}
			}
			if len(events) > 0 {
				return events, nil
			}
		case ev := <-w.linkCh:
			log.Info("link ev:", ev)
		case ev := <-w.routeCh:
			log.Info("route ev:", ev)
			if ev.Route.Protocol == RTPROT_GOPLANE {
				continue
			}
			return []proto.EntryEvent{proto.EntryEvent{
				Entry: &NetlinkRouteEntry{
					route: &ev.Route,
				},
				IsDel: ev.Type == uint16(RTM_DELROUTE),
				From:  proto.PROTO_NETLINK,
			}}, nil
		}
	}
	return nil, nil
}

func (w *NetlinkEntryWatcher) Close() error {
	close(w.closeCh)
	w.socket.Close()
	return nil
}

func (w *NetlinkEntryWatcher) serve() error {
	if err := netlink.LinkSubscribe(w.linkCh, w.closeCh); err != nil {
		return err
	}
	if err := netlink.RouteSubscribe(w.routeCh, w.closeCh); err != nil {
		return err
	}
	for {
		msgs, err := w.socket.Receive()
		if err != nil {
			log.Fatal(err)
		}
		w.neighCh <- msgs
	}
	return nil
}

func (p *NetlinkProtocol) WatchEntry() (proto.EntryWatcher, error) {
	s, err := nl.Subscribe(syscall.NETLINK_ROUTE, uint(RTMGRP_NEIGH), uint(RTMGRP_LINK), uint(RTMGRP_NOTIFY), uint(RTMGRP_IPV4_IFADDR))
	if err != nil {
		return nil, err
	}
	neighCh := make(chan []syscall.NetlinkMessage)
	linkCh := make(chan netlink.LinkUpdate)
	routeCh := make(chan netlink.RouteUpdate)
	closeCh := make(chan struct{})
	w := &NetlinkEntryWatcher{
		socket:  s,
		p:       p,
		neighCh: neighCh,
		linkCh:  linkCh,
		routeCh: routeCh,
		closeCh: closeCh,
	}
	go func() {
		log.Fatal(w.serve())
	}()
	return w, nil
}
