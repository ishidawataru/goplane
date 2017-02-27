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

package protocol

import (
	"fmt"
	"net"
	"time"

	log "github.com/Sirupsen/logrus"
	bgpapi "github.com/osrg/gobgp/api"
	bgpconfig "github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet/bgp"
	bgpserver "github.com/osrg/gobgp/server"
	bgptable "github.com/osrg/gobgp/table"
	"github.com/osrg/goplane/config"
)

type GoBGPEntry struct {
	nlri bgp.AddrPrefixInterface
	path []*bgptable.Path
	vrf  *config.VirtualNetwork
}

func (e *GoBGPEntry) NLRI() bgp.AddrPrefixInterface {
	return e.nlri
}

func (e *GoBGPEntry) Match() Match {
	f := bgp.AfiSafiToRouteFamily(e.nlri.AFI(), e.nlri.SAFI())
	switch f {
	case bgp.RF_IPv4_UC, bgp.RF_IPv6_UC:
		_, n, _ := net.ParseCIDR(e.nlri.String())
		return &LPMatch{
			Prefix: n,
		}
	case bgp.RF_EVPN:
		switch t := e.nlri.(*bgp.EVPNNLRI).RouteTypeData.(type) {
		case *bgp.EVPNMacIPAdvertisementRoute:
			return &L2VPNMatch{
				VRF: *e.vrf,
				MAC: t.MacAddress,
				IP:  t.IPAddress,
			}
		case *bgp.EVPNMulticastEthernetTagRoute:
			return &L2VPNMcastMatch{
				VRF: *e.vrf,
			}
		}
	case bgp.RF_FS_IPv4_UC:
		m := make(map[bgp.BGPFlowSpecType]bgp.FlowSpecComponentInterface)
		for _, v := range e.nlri.(*bgp.FlowSpecIPv4Unicast).Value {
			m[v.Type()] = v
		}
		match := &ACLMatch{}
		if v, ok := m[bgp.FLOW_SPEC_TYPE_DST_PREFIX]; ok {
			_, dst, _ := net.ParseCIDR(v.(*bgp.FlowSpecDestinationPrefix).Prefix.String())
			match.DstIPPrefix = dst
		}
		if v, ok := m[bgp.FLOW_SPEC_TYPE_SRC_PREFIX]; ok {
			_, src, _ := net.ParseCIDR(v.(*bgp.FlowSpecDestinationPrefix).Prefix.String())
			match.SrcIPPrefix = src
		}
		if v, ok := m[bgp.FLOW_SPEC_TYPE_IP_PROTO]; ok {
			if len(v.(*bgp.FlowSpecComponent).Items) != 1 {
				log.Errorf("ip proto len must be 1")
			}
			match.IPProto = v.(*bgp.FlowSpecComponent).Items[0].Value
		}
		return match
	}
	return nil
}

func (e *GoBGPEntry) Action() Action {
	f := bgp.AfiSafiToRouteFamily(e.nlri.AFI(), e.nlri.SAFI())
	switch f {
	case bgp.RF_FS_IPv4_UC:
		return &DropAction{}
	default:
		info := make([]*NexthopInfo, 0, len(e.path))
		for _, p := range e.path {
			info = append(info, &NexthopInfo{
				Nexthop: p.GetNexthop(),
			})
		}
		return &ViaAction{
			Nexthops: info,
		}
	}
}

type GoBGPProtocol struct {
	server *bgpserver.BgpServer
	pathCh chan *bgptable.Path
	config *bgpconfig.BgpConfigSet
}

func NewGoBGPProtocol() *GoBGPProtocol {
	server := bgpserver.NewBgpServer()
	go server.Serve()
	proto := &GoBGPProtocol{
		server: server,
		pathCh: make(chan *bgptable.Path),
	}
	grpcServer := bgpapi.NewGrpcServer(server, ":50051")
	go func() {
		if err := grpcServer.Serve(); err != nil {
			log.Fatalf("failed to listen grpc port: %s", err)
		}
	}()
	go proto.serve()
	return proto
}

func (p *GoBGPProtocol) Type() ProtocolType {
	return PROTO_GOBGP
}

func (p *GoBGPProtocol) SetRouterID(id net.IP) error {
	return nil
}

func (p *GoBGPProtocol) UpdateConfig(newConfig *bgpconfig.BgpConfigSet) error {
	var added, deleted, updated []bgpconfig.Neighbor
	var updatePolicy bool

	bgpServer := p.server

	if p.config == nil {
		p.config = newConfig
		if err := bgpServer.Start(&newConfig.Global); err != nil {
			return fmt.Errorf("failed to set global config: %s", err)
		}
		if newConfig.Zebra.Config.Enabled {
			if err := bgpServer.StartZebraClient(&newConfig.Zebra.Config); err != nil {
				return fmt.Errorf("failed to set zebra config: %s", err)
			}
		}
		if len(newConfig.Collector.Config.Url) > 0 {
			if err := bgpServer.StartCollector(&newConfig.Collector.Config); err != nil {
				return fmt.Errorf("failed to set collector config: %s", err)
			}
		}
		for _, c := range newConfig.RpkiServers {
			if err := bgpServer.AddRpki(&c.Config); err != nil {
				return fmt.Errorf("failed to set rpki config: %s", err)
			}
		}
		for _, c := range newConfig.BmpServers {
			if err := bgpServer.AddBmp(&c.Config); err != nil {
				return fmt.Errorf("failed to set bmp config: %s", err)
			}
		}
		for _, c := range newConfig.MrtDump {
			if len(c.Config.FileName) == 0 {
				continue
			}
			if err := bgpServer.EnableMrt(&c.Config); err != nil {
				return fmt.Errorf("failed to set mrt config: %s", err)
			}
		}
		p := bgpconfig.ConfigSetToRoutingPolicy(newConfig)
		if err := bgpServer.UpdatePolicy(*p); err != nil {
			return fmt.Errorf("failed to set routing policy: %s", err)
		}

		added = newConfig.Neighbors
		//		if opts.GracefulRestart {
		//			for i, n := range added {
		//				if n.GracefulRestart.Config.Enabled {
		//					added[i].GracefulRestart.State.LocalRestarting = true
		//				}
		//			}
		//		}

	} else {
		added, deleted, updated, updatePolicy = bgpconfig.UpdateConfig(p.config, newConfig)
		if updatePolicy {
			log.Info("Policy config is updated")
			policy := bgpconfig.ConfigSetToRoutingPolicy(newConfig)
			bgpServer.UpdatePolicy(*policy)
		}
		p.config = newConfig
	}

	for i, p := range added {
		log.Infof("Peer %v is added", p.Config.NeighborAddress)
		bgpServer.AddNeighbor(&added[i])
	}
	for i, p := range deleted {
		log.Infof("Peer %v is deleted", p.Config.NeighborAddress)
		bgpServer.DeleteNeighbor(&deleted[i])
	}
	for i, p := range updated {
		log.Infof("Peer %v is updated", p.Config.NeighborAddress)
		u, _ := bgpServer.UpdateNeighbor(&updated[i])
		updatePolicy = updatePolicy || u
	}

	if updatePolicy {
		bgpServer.SoftResetIn("", bgp.RouteFamily(0))
	}

	return nil
}

func (p *GoBGPProtocol) serve() error {
	for {
		select {
		case path := <-p.pathCh:
			log.Info(path)
			if _, err := p.server.AddPath("", []*bgptable.Path{path}); err != nil {
				log.Fatal(err)
				return err
			}
		}
	}
}

func (p *GoBGPProtocol) makePath(e Entry) (*bgptable.Path, error) {
	var nlri bgp.AddrPrefixInterface
	if e.Action().Type() != ACTION_VIA {
		return nil, fmt.Errorf("unsupported action type: %d", e.Action().Type())
	}
	via := e.Action().(*ViaAction).Nexthops[0].Nexthop
	if via == nil {
		via = net.ParseIP("0.0.0.0")
	}
	pattrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP)}
	mp := true

	routerID := net.ParseIP(p.server.GetServer().Config.RouterId)

	switch e.Match().Type() {
	case MATCH_LP:
		m := e.Match().(*LPMatch)
		n := m.Prefix
		ones, _ := n.Mask.Size()
		if n.IP.To4() == nil {
			nlri = bgp.NewIPv6AddrPrefix(uint8(ones), n.IP.String())
		} else {
			mp = false
			nlri = bgp.NewIPAddrPrefix(uint8(ones), n.IP.String())
			pattrs = append(pattrs, bgp.NewPathAttributeNextHop(via.String()))
		}
	case MATCH_L2VPN:
		m := e.Match().(*L2VPNMatch)
		rd, _ := bgp.ParseRouteDistinguisher(m.VRF.RD)
		macIpAdv := &bgp.EVPNMacIPAdvertisementRoute{
			RD: rd,
			ESI: bgp.EthernetSegmentIdentifier{
				Type: bgp.ESI_ARBITRARY,
			},
			MacAddressLength: 48,
			MacAddress:       m.MAC,
			IPAddressLength:  0,
			Labels:           []uint32{uint32(m.VRF.VNI)},
			ETag:             uint32(m.VRF.Etag),
		}
		nlri = bgp.NewEVPNNLRI(bgp.EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT, 0, macIpAdv)

		isTransitive := true
		o := bgp.NewOpaqueExtended(isTransitive)
		o.SubType = bgp.EC_SUBTYPE_ENCAPSULATION
		o.Value = &bgp.EncapExtended{bgp.TUNNEL_TYPE_VXLAN}
		pattrs = append(pattrs, bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{o}))
	case MATCH_L2VPN_MCAST:
		m := e.Match().(*L2VPNMcastMatch)
		rd, _ := bgp.ParseRouteDistinguisher(m.VRF.RD)
		multicastEtag := &bgp.EVPNMulticastEthernetTagRoute{
			RD:              rd,
			IPAddressLength: uint8(32),
			IPAddress:       routerID,
			ETag:            uint32(m.VRF.Etag),
		}
		nlri = bgp.NewEVPNNLRI(bgp.EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG, 0, multicastEtag)
		id := &bgp.IngressReplTunnelID{
			Value: routerID,
		}
		pattrs = append(pattrs, bgp.NewPathAttributePmsiTunnel(bgp.PMSI_TUNNEL_TYPE_INGRESS_REPL, false, 0, id))

	}
	if mp {
		pattrs = append(pattrs, bgp.NewPathAttributeMpReachNLRI(via.String(), []bgp.AddrPrefixInterface{nlri}))
	}
	return bgptable.NewPath(nil, nlri, false, pattrs, time.Now(), false), nil
}

func (p *GoBGPProtocol) AddEntry(e Entry) error {
	path, err := p.makePath(e)
	if err != nil {
		return err
	}
	p.pathCh <- path
	return nil
}

func (p *GoBGPProtocol) DeleteEntry(e Entry) error {
	path, err := p.makePath(e)
	if err != nil {
		return err
	}
	path.IsWithdraw = true
	p.pathCh <- path
	return nil
}

type GoBGPEntryWatcher struct {
	watcher *bgpserver.Watcher
}

func makeEntryEvents(paths [][]*bgptable.Path) []EntryEvent {
	events := make([]EntryEvent, 0, len(paths))
	for _, ps := range paths {
		list := make([]*bgptable.Path, 0, len(ps))
		isDel := false
		for _, p := range ps {
			if p.IsLocal() {
				continue
			}
			if p.IsWithdraw {
				isDel = true
			}
			list = append(list, p)
		}
		if len(list) == 0 {
			continue
		}
		var vrf *config.VirtualNetwork
		nlri := list[0].GetNlri()
		family := bgp.AfiSafiToRouteFamily(nlri.AFI(), nlri.SAFI())
		if family == bgp.RF_EVPN {
			vrf = &config.VirtualNetwork{
				RD: nlri.(*bgp.EVPNNLRI).RD().String(),
			}
		}
		events = append(events, EntryEvent{
			Entry: &GoBGPEntry{
				nlri: nlri,
				path: list,
				vrf:  vrf,
			},
			IsDel: isDel,
			From:  PROTO_GOBGP,
		})
	}
	return events
}

func (w *GoBGPEntryWatcher) Recv() ([]EntryEvent, error) {
	for {
		e := (<-w.watcher.Event()).(*bgpserver.WatchEventBestPath)
		var pathList [][]*bgptable.Path
		if len(e.MultiPathList) > 0 {
			pathList = e.MultiPathList
		} else {
			pathList = make([][]*bgptable.Path, 0, len(e.PathList))
			for _, p := range e.PathList {
				pathList = append(pathList, []*bgptable.Path{p})
			}
		}
		events := makeEntryEvents(pathList)
		if len(events) > 0 {
			return events, nil
		}
	}
	return nil, nil
}

func (w *GoBGPEntryWatcher) Close() error {
	w.watcher.Stop()
	return nil
}

func (p *GoBGPProtocol) WatchEntry() (EntryWatcher, error) {
	watcher := p.server.Watch(bgpserver.WatchBestPath(true))
	return &GoBGPEntryWatcher{
		watcher: watcher,
	}, nil
}

func (p *GoBGPProtocol) AddVirtualNetwork(routerID string, c config.VirtualNetwork) error {
	rd, err := bgp.ParseRouteDistinguisher(c.RD)
	if err != nil {
		return err
	}
	rt, err := bgp.ParseRouteTarget(c.RD)
	if err != nil {
		return err
	}
	err = p.server.AddVrf(c.RD, 0, rd, []bgp.ExtendedCommunityInterface{rt}, []bgp.ExtendedCommunityInterface{rt})
	if err != nil {
		return err
	}
	return p.AddEntry(&BaseEntry{
		match: &L2VPNMcastMatch{
			VRF: c,
		},
		action: &ViaAction{},
	})
}

func (p *GoBGPProtocol) DeleteVirtualNetwork(c config.VirtualNetwork) error {
	return p.server.DeleteVrf(c.RD)
}
