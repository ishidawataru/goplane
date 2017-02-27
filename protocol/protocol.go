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

	"github.com/osrg/goplane/config"
)

type Family int

const (
	_ Family = iota
	V4
	V6
)

type ProtocolType int

const (
	_ ProtocolType = iota
	PROTO_NETLINK
	PROTO_IPTABLES
	PROTO_GOBGP
)

type MatchType int

const (
	_           MatchType = iota
	MATCH_LP              // Longest Prefix Match
	MATCH_L2VPN           // L2VPN Match
	MATCH_L2VPN_MCAST
	MATCH_ACL
)

type LPMatch struct {
	Prefix *net.IPNet
}

func (m *LPMatch) Type() MatchType {
	return MATCH_LP
}

func (m *LPMatch) String() string {
	return m.Prefix.String()
}

type L2VPNMatch struct {
	VRF config.VirtualNetwork
	MAC net.HardwareAddr
	IP  net.IP
}

func (m *L2VPNMatch) Type() MatchType {
	return MATCH_L2VPN
}

func (m *L2VPNMatch) String() string {
	return fmt.Sprintf("{VRF: %s, MAC: %s, IP: %s}", m.VRF.RD, m.MAC, m.IP)
}

type L2VPNMcastMatch struct {
	VRF config.VirtualNetwork
}

func (m *L2VPNMcastMatch) Type() MatchType {
	return MATCH_L2VPN_MCAST
}

func (m *L2VPNMcastMatch) String() string {
	return fmt.Sprintf("{VRF: %s}", m.VRF.RD)
}

type ACLMatch struct {
	SrcIPPrefix *net.IPNet
	DstIPPrefix *net.IPNet
	IPProto     int
}

func (m *ACLMatch) Type() MatchType {
	return MATCH_ACL
}

func (m *ACLMatch) String() string {
	return fmt.Sprintf("{SRC: %s, DST: %s, IPProto: %d", m.SrcIPPrefix, m.DstIPPrefix, m.IPProto)
}

type Match interface {
	Type() MatchType
	String() string
}

type ActionType int

const (
	_          ActionType = iota
	ACTION_VIA            // Nexthop Action
	ACTION_DROP
)

type NexthopInfo struct {
	Nexthop   net.IP
	LinkIndex int
}

func (i *NexthopInfo) String() string {
	return fmt.Sprintf("{Nexthop: %s, Link: %d}", i.Nexthop, i.LinkIndex)
}

type ViaAction struct {
	Nexthops []*NexthopInfo
}

func (a *ViaAction) Type() ActionType {
	return ACTION_VIA
}

func (a *ViaAction) String() string {
	return fmt.Sprintf("%v", a.Nexthops)
}

type DropAction struct {
}

func (a *DropAction) Type() ActionType {
	return ACTION_DROP
}

func (a *DropAction) String() string {
	return "DROP"
}

type Action interface {
	Type() ActionType
	String() string
}

type BaseEntry struct {
	match  Match
	action Action
}

func (e *BaseEntry) Match() Match {
	return e.match
}

func (e *BaseEntry) Action() Action {
	return e.action
}

type Entry interface {
	Match() Match
	Action() Action
}

type EntryEvent struct {
	Entry Entry
	IsDel bool
	From  ProtocolType
}

type EntryWatcher interface {
	Recv() ([]EntryEvent, error)
	Close() error
}

type Protocol interface {
	Type() ProtocolType
	AddEntry(Entry) error
	DeleteEntry(Entry) error
	WatchEntry() (EntryWatcher, error)

	SetRouterID(net.IP) error

	AddVirtualNetwork(string, config.VirtualNetwork) error
	DeleteVirtualNetwork(config.VirtualNetwork) error
	//
	//	AddVRFRoute(config.VirtualNetwork, Route) error
	//	DeleteVRFRoute(config.VirtualNetwork, Route) error
}
