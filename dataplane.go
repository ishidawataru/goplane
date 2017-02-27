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

package main

import (
	"fmt"
	"net"
	"sync"

	log "github.com/Sirupsen/logrus"
	"github.com/osrg/goplane/config"
	proto "github.com/osrg/goplane/protocol"
)

type Dataplane struct {
	routerID     net.IP
	protos       map[proto.ProtocolType]proto.Protocol
	routeEventCh chan []proto.EntryEvent
	m            sync.RWMutex
}

func NewDataplane() *Dataplane {
	d := &Dataplane{
		protos:       make(map[proto.ProtocolType]proto.Protocol),
		routeEventCh: make(chan []proto.EntryEvent, 0),
	}
	go func() {
		log.Fatal(d.serve())
	}()
	return d
}

func (d *Dataplane) serve() error {
	for {
		for _, ev := range <-d.routeEventCh {
			log.Info("ev:", ev)
			d.m.RLock()
			for _, proto := range d.protos {
				if ev.From == proto.Type() || ev.Entry.Match() == nil {
					continue
				}
				var err error
				if ev.IsDel {
					err = proto.DeleteEntry(ev.Entry)
				} else {
					err = proto.AddEntry(ev.Entry)
				}
				if err != nil {
					log.Errorf("err: %v", err)
				}
			}
			d.m.RUnlock()
		}
	}
	return nil
}

func (d *Dataplane) SetRouterID(id net.IP) error {
	d.m.RLock()
	defer d.m.RUnlock()
	for _, proto := range d.protos {
		if err := proto.SetRouterID(id); err != nil {
			return err
		}
	}
	return nil
}

func (d *Dataplane) AddProtocol(p proto.Protocol) error {
	d.m.Lock()
	defer d.m.Unlock()
	if _, y := d.protos[p.Type()]; y {
		return fmt.Errorf("protocol %d already exists", p.Type())
	}
	d.protos[p.Type()] = p
	w, err := p.WatchEntry()
	if err != nil {
		return err
	}
	if w != nil {
		go func() {
			for {
				rs, err := w.Recv()
				if err != nil {
					log.Fatalf("failed recv routes: %s", err)
				}
				d.routeEventCh <- rs
			}
		}()
	}
	return nil
}

func (d *Dataplane) AddVirtualNetwork(c config.VirtualNetwork) error {
	d.m.RLock()
	defer d.m.RUnlock()
	for _, proto := range d.protos {
		if err := proto.AddVirtualNetwork(d.routerID.String(), c); err != nil {
			return err
		}
	}
	return nil
}

func (d *Dataplane) DeleteVirtualNetwork(c config.VirtualNetwork) error {
	d.m.RLock()
	defer d.m.RUnlock()
	for _, proto := range d.protos {
		if err := proto.DeleteVirtualNetwork(c); err != nil {
			return err
		}
	}
	return nil
}
