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

package iptables

import (
	"fmt"
	"net"

	log "github.com/Sirupsen/logrus"
	"github.com/coreos/go-iptables/iptables"
	"github.com/osrg/gobgp/packet/bgp"
	"github.com/osrg/goplane/config"
	proto "github.com/osrg/goplane/protocol"
)

type ev struct {
	nlri  bgp.AddrPrefixInterface
	isDel bool
}

func FlowSpec2IptablesRule(nlri []bgp.FlowSpecComponentInterface) ([]string, error) {
	spec := make([]string, 0, len(nlri))
	m := make(map[bgp.BGPFlowSpecType]bgp.FlowSpecComponentInterface)
	for _, v := range nlri {
		m[v.Type()] = v
	}

	if v, ok := m[bgp.FLOW_SPEC_TYPE_DST_PREFIX]; ok {
		prefix := v.(*bgp.FlowSpecDestinationPrefix).Prefix.String()
		spec = append(spec, "-d")
		spec = append(spec, prefix)
	}

	if v, ok := m[bgp.FLOW_SPEC_TYPE_SRC_PREFIX]; ok {
		prefix := v.(*bgp.FlowSpecSourcePrefix).Prefix.String()
		spec = append(spec, "-s")
		spec = append(spec, prefix)
	}

	if v, ok := m[bgp.FLOW_SPEC_TYPE_IP_PROTO]; ok {
		if len(v.(*bgp.FlowSpecComponent).Items) != 1 {
			return nil, fmt.Errorf("ip proto len must be 1")
		}
		proto := bgp.Protocol(v.(*bgp.FlowSpecComponent).Items[0].Value).String()
		spec = append(spec, "-p")
		spec = append(spec, proto)
	}

	spec = append(spec, "-j")
	spec = append(spec, "DROP")

	return spec, nil
}

type IPTablesProtocol struct {
	config config.Iptables
	ch     chan *ev
	list   []*bgp.FlowSpecNLRI
}

func NewIPTablesProtocol(c config.Iptables) *IPTablesProtocol {
	p := &IPTablesProtocol{
		config: c,
		ch:     make(chan *ev),
		list:   make([]*bgp.FlowSpecNLRI, 0),
	}
	go p.serve()
	return p
}

func (p *IPTablesProtocol) serve() error {

	ipt, err := iptables.New()
	if err != nil {
		log.Fatalf("%s", err)
	}

	table := "filter"
	chain := "FLOWSPEC"
	if p.config.Chain != "" {
		chain = p.config.Chain
	}

	if err := ipt.ClearChain(table, chain); err != nil {
		return fmt.Errorf("failed to clear chain: %s", err)
	}
	log.Infof("cleared iptables chain: %s, table: %s", chain, table)

	for ev := range p.ch {
		f := bgp.AfiSafiToRouteFamily(ev.nlri.AFI(), ev.nlri.SAFI())
		if f != bgp.RF_FS_IPv4_UC {
			continue
		}

		nlri := &ev.nlri.(*bgp.FlowSpecIPv4Unicast).FlowSpecNLRI

		spec, err := FlowSpec2IptablesRule(nlri.Value)
		if err != nil {
			log.Warnf("failed to convert flowspec spec to iptables rule: %s", err)
			continue
		}

		idx := 0
		var q *bgp.FlowSpecNLRI
		if ev.isDel {
			found := false
			for idx, q = range p.list {
				result, err := bgp.CompareFlowSpecNLRI(nlri, q)
				if err != nil {
					log.Fatalf("%s", err)
				}
				if result == 0 {
					found = true
					break
				}
			}
			if !found {
				log.Warnf("not found: %s", nlri)
			}
			p.list = append(p.list[:idx], p.list[idx+1:]...)
			if err := ipt.Delete(table, chain, spec...); err != nil {
				log.Errorf("failed to delete: %s", err)
			} else {
				log.Debugf("delete iptables rule: %v", spec)
			}
		} else {
			found := false
			for idx, q = range p.list {
				result, err := bgp.CompareFlowSpecNLRI(nlri, q)
				if err != nil {
					log.Fatalf("%s", err)
				}
				if result > 0 {
					found = true
					p.list = append(p.list[:idx], append([]*bgp.FlowSpecNLRI{nlri}, p.list[idx:]...)...)
					idx += 1
					break
				} else if result == 0 {
					found = true
					break
				}
			}

			if !found {
				p.list = append(p.list, nlri)
				idx = len(p.list)
			}

			if y, _ := ipt.Exists(table, chain, spec...); y {
				log.Warnf("already exists: %v", spec)
			} else if err := ipt.Insert(table, chain, idx, spec...); err != nil {
				log.Errorf("failed to insert: %s", err)
			} else {
				log.Debugf("insert iptables rule: %v", spec)
			}
		}
	}
	return nil
}

func (p *IPTablesProtocol) AddEntry(e proto.Entry) error {
	if e.Match().Type() != proto.MATCH_ACL {
		return nil
	}
	p.ch <- &ev{
		nlri: e.(*proto.GoBGPEntry).NLRI(),
	}
	return nil
}

func (p *IPTablesProtocol) DeleteEntry(e proto.Entry) error {
	if e.Match().Type() != proto.MATCH_ACL {
		return nil
	}
	p.ch <- &ev{
		nlri:  e.(*proto.GoBGPEntry).NLRI(),
		isDel: true,
	}
	return nil
}

func (p *IPTablesProtocol) WatchEntry() (proto.EntryWatcher, error) {
	return nil, nil
}

func (p *IPTablesProtocol) SetRouterID(net.IP) error {
	return nil
}

func (p *IPTablesProtocol) AddVirtualNetwork(string, config.VirtualNetwork) error {
	return nil
}

func (p *IPTablesProtocol) DeleteVirtualNetwork(config.VirtualNetwork) error {
	return nil
}

func (p *IPTablesProtocol) Type() proto.ProtocolType {
	return proto.PROTO_IPTABLES
}
