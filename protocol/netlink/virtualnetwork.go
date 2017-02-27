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
	"syscall"

	log "github.com/Sirupsen/logrus"
	"github.com/osrg/goplane/config"
	proto "github.com/osrg/goplane/protocol"
	"github.com/vishvananda/netlink"
	"gopkg.in/tomb.v2"
)

type VirtualNetwork struct {
	t        tomb.Tomb
	connMap  map[string]net.Conn
	config   config.VirtualNetwork
	floodCh  chan []byte
	routerId string
}

func (n *VirtualNetwork) Stop() {
	n.t.Kill(fmt.Errorf("admin stop"))
}

func (n *VirtualNetwork) Serve() error {
	log.Debugf("vtep intf: %s", n.config.VtepInterface)
	link, err := netlink.LinkByName(n.config.VtepInterface)
	master := 0
	if err == nil {
		log.Debug("link type:", link.Type())
		vtep := link.(*netlink.Vxlan)
		err = netlink.LinkSetDown(vtep)
		log.Debugf("set %s down", n.config.VtepInterface)
		if err != nil {
			return fmt.Errorf("failed to set link %s down", n.config.VtepInterface)
		}
		master = vtep.MasterIndex
		log.Debugf("del %s", n.config.VtepInterface)
		err = netlink.LinkDel(link)
		if err != nil {
			return fmt.Errorf("failed to del %s", n.config.VtepInterface)
		}
	}

	if master > 0 {
		b, _ := netlink.LinkByIndex(master)
		br := b.(*netlink.Bridge)
		err = netlink.LinkSetDown(br)
		log.Debugf("set %s down", br.LinkAttrs.Name)
		if err != nil {
			return fmt.Errorf("failed to set %s down", br.LinkAttrs.Name)
		}
		log.Debugf("del %s", br.LinkAttrs.Name)
		err = netlink.LinkDel(br)
		if err != nil {
			return fmt.Errorf("failed to del %s", br.LinkAttrs.Name)
		}
	}

	brName := fmt.Sprintf("br%d", n.config.VNI)

	b, err := netlink.LinkByName(brName)
	if err == nil {
		br := b.(*netlink.Bridge)
		err = netlink.LinkSetDown(br)
		log.Debugf("set %s down", br.LinkAttrs.Name)
		if err != nil {
			return fmt.Errorf("failed to set %s down", br.LinkAttrs.Name)
		}
		log.Debugf("del %s", br.LinkAttrs.Name)
		err = netlink.LinkDel(br)
		if err != nil {
			return fmt.Errorf("failed to del %s", br.LinkAttrs.Name)
		}
	}

	br := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{
			Name: brName,
		},
	}

	log.Debugf("add %s", brName)
	err = netlink.LinkAdd(br)
	if err != nil {
		return fmt.Errorf("failed to add link %s. %s", brName, err)
	}
	err = netlink.LinkSetUp(br)
	if err != nil {
		return fmt.Errorf("failed to set %s up", brName)
	}

	link = &netlink.Vxlan{
		LinkAttrs: netlink.LinkAttrs{
			Name: n.config.VtepInterface,
		},
		VxlanId: int(n.config.VNI),
		SrcAddr: net.ParseIP(n.routerId),
	}

	log.Debugf("add %s", n.config.VtepInterface)
	err = netlink.LinkAdd(link)
	if err != nil {
		return fmt.Errorf("failed to add link %s. %s", n.config.VtepInterface, err)
	}
	err = netlink.LinkSetUp(link)
	if err != nil {
		return fmt.Errorf("failed to set %s up", n.config.VtepInterface)
	}

	err = netlink.LinkSetMaster(link, br)
	if err != nil {
		return fmt.Errorf("failed to set master %s dev %s", brName, n.config.VtepInterface)
	}

	for _, member := range n.config.MemberInterfaces {
		m, err := netlink.LinkByName(member)
		if err != nil {
			log.Errorf("can't find %s", member)
			continue
		}
		err = netlink.LinkSetUp(m)
		if err != nil {
			return fmt.Errorf("failed to set %s up", member)
		}
		err = netlink.LinkSetMaster(m, br)
		if err != nil {
			return fmt.Errorf("failed to set master %s dev %s", brName, member)
		}
	}

	for _, member := range n.config.SniffInterfaces {
		n.t.Go(func() error {
			return n.sniffPkt(member)
		})
	}

	for {
		select {
		case <-n.t.Dying():
			log.Errorf("stop virtualnetwork %s", n.config.RD)
			for h, conn := range n.connMap {
				log.Debugf("close udp connection to %s", h)
				conn.Close()
			}
			return nil
		case p := <-n.floodCh:
			err = n.flood(p)
			if err != nil {
				log.Errorf("flood failed. kill main loop. err: %s", err)
				return err
			}
		}
	}
}

func (f *VirtualNetwork) ModConnMap(e proto.Entry, del bool) error {
	addr := e.Action().(*proto.ViaAction).Nexthops[0].Nexthop.String()
	log.Debugf("mod cannection map: nh %s, vtep addr %s withdraw %t", addr, del)
	if del {
		_, ok := f.connMap[addr]
		if !ok {
			return fmt.Errorf("can't find %s conn", addr)
		}

		f.connMap[addr].Close()
		delete(f.connMap, addr)
	} else {
		_, ok := f.connMap[addr]
		if ok {
			log.Debugf("refresh. close connection to %s", addr)
			f.connMap[addr].Close()
			delete(f.connMap, addr)
		}
		udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", addr, f.config.VxlanPort))
		if err != nil {
			log.Fatal(err)
		}

		log.Debugf("connect to %s", addr)
		conn, err := net.DialUDP("udp", nil, udpAddr)
		if err != nil {
			log.Warnf("failed to dial UDP(%s) %s", addr, err)
			return nil
		}
		f.connMap[addr] = conn
	}
	return nil
}

func (f *VirtualNetwork) ModFDB(e proto.Entry, del bool) error {
	mac := e.Match().(*proto.L2VPNMatch).MAC
	nh := e.Action().(*proto.ViaAction).Nexthops[0].Nexthop
	log.WithFields(log.Fields{
		"Topic": "VirtualNetwork",
		"Etag":  f.config.Etag,
	}).Debugf("modFdb new path, mac: %s, nexthop: %s, withdraw: %t", mac, nh, del)

	link, err := netlink.LinkByName(f.config.VtepInterface)
	if err != nil {
		log.WithFields(log.Fields{
			"Topic": "VirtualNetwork",
			"Etag":  f.config.Etag,
		}).Debugf("failed lookup link by name: %s", f.config.VtepInterface)
		return nil
	}

	n := &netlink.Neigh{
		LinkIndex:    link.Attrs().Index,
		Family:       int(netlink.NDA_VNI),
		State:        int(netlink.NUD_NOARP | netlink.NUD_PERMANENT),
		Type:         syscall.RTM_NEWNEIGH,
		Flags:        int(netlink.NTF_SELF),
		IP:           nh,
		HardwareAddr: mac,
	}

	if del {
		err = netlink.NeighDel(n)
		if err != nil {
			log.WithFields(log.Fields{
				"Topic": "VirtualNetwork",
				"Etag":  f.config.Etag,
			}).Errorf("failed to del fdb: %s, %s", n, err)
		}
	} else {
		err = netlink.NeighAppend(n)
		if err != nil {
			log.WithFields(log.Fields{
				"Topic": "VirtualNetwork",
				"Etag":  f.config.Etag,
			}).Debugf("failed to add fdb: %s, %s", n, err)
		}
	}
	return err
}

func (f *VirtualNetwork) flood(pkt []byte) error {
	vxlanHeader := NewVXLAN(f.config.VNI)
	b := vxlanHeader.Serialize()
	b = append(b, pkt...)

	for _, c := range f.connMap {
		cnt, err := c.Write(b)
		log.WithFields(log.Fields{
			"Topic": "VirtualNetwork",
			"Etag":  f.config.Etag,
		}).Debugf("send to %s: cnt:%d, err:%s", c.RemoteAddr(), cnt, err)
		if err != nil {
			return err
		}
	}

	return nil
}

func (f *VirtualNetwork) sniffPkt(ifname string) error {
	conn, err := NewPFConn(ifname)
	if err != nil {
		return err
	}
	buf := make([]byte, 2048)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			log.Errorf("failed to recv from %s, err: %s", conn, err)
			return err
		}
		log.WithFields(log.Fields{
			"Topic": "VirtualNetwork",
			"Etag":  f.config.Etag,
		}).Debugf("recv from %s, len: %d", conn, n)
		f.floodCh <- buf[:n]
	}
}

func NewVirtualNetwork(routerID string, config config.VirtualNetwork) *VirtualNetwork {
	floodCh := make(chan []byte, 16)

	return &VirtualNetwork{
		config:   config,
		connMap:  map[string]net.Conn{},
		floodCh:  floodCh,
		routerId: routerID,
	}
}
