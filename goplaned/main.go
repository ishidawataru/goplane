// Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
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
	log "github.com/Sirupsen/logrus"
	"github.com/Sirupsen/logrus/hooks/syslog"
	"github.com/jessevdk/go-flags"
	bgpconf "github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet"
	bgpserver "github.com/osrg/gobgp/server"
	"github.com/osrg/goplane/config"
	"github.com/osrg/goplane/netlink"
	"io/ioutil"
	"log/syslog"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
)

type Dataplaner interface {
	Serve() error
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP)

	var opts struct {
		ConfigFile    string `short:"f" long:"config-file" description:"specifying a config file"`
		LogLevel      string `short:"l" long:"log-level" description:"specifying log level"`
		LogPlain      bool   `short:"p" long:"log-plain" description:"use plain format for logging (json by default)"`
		UseSyslog     string `short:"s" long:"syslog" description:"use syslogd"`
		Facility      string `long:"syslog-facility" description:"specify syslog facility"`
		DisableStdlog bool   `long:"disable-stdlog" description:"disable standard logging"`
	}
	_, err := flags.Parse(&opts)
	if err != nil {
		os.Exit(1)
	}

	switch opts.LogLevel {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	default:
		log.SetLevel(log.InfoLevel)
	}

	if opts.DisableStdlog == true {
		log.SetOutput(ioutil.Discard)
	} else {
		log.SetOutput(os.Stdout)
	}

	if opts.UseSyslog != "" {
		dst := strings.SplitN(opts.UseSyslog, ":", 2)
		network := ""
		addr := ""
		if len(dst) == 2 {
			network = dst[0]
			addr = dst[1]
		}

		facility := syslog.Priority(0)
		switch opts.Facility {
		case "kern":
			facility = syslog.LOG_KERN
		case "user":
			facility = syslog.LOG_USER
		case "mail":
			facility = syslog.LOG_MAIL
		case "daemon":
			facility = syslog.LOG_DAEMON
		case "auth":
			facility = syslog.LOG_AUTH
		case "syslog":
			facility = syslog.LOG_SYSLOG
		case "lpr":
			facility = syslog.LOG_LPR
		case "news":
			facility = syslog.LOG_NEWS
		case "uucp":
			facility = syslog.LOG_UUCP
		case "cron":
			facility = syslog.LOG_CRON
		case "authpriv":
			facility = syslog.LOG_AUTHPRIV
		case "ftp":
			facility = syslog.LOG_FTP
		case "local0":
			facility = syslog.LOG_LOCAL0
		case "local1":
			facility = syslog.LOG_LOCAL1
		case "local2":
			facility = syslog.LOG_LOCAL2
		case "local3":
			facility = syslog.LOG_LOCAL3
		case "local4":
			facility = syslog.LOG_LOCAL4
		case "local5":
			facility = syslog.LOG_LOCAL5
		case "local6":
			facility = syslog.LOG_LOCAL6
		case "local7":
			facility = syslog.LOG_LOCAL7
		}

		hook, err := logrus_syslog.NewSyslogHook(network, addr, syslog.LOG_INFO|facility, "bgpd")
		if err != nil {
			log.Error("Unable to connect to syslog daemon, ", opts.UseSyslog)
			os.Exit(1)
		} else {
			log.AddHook(hook)
		}
	}

	if opts.LogPlain == false {
		log.SetFormatter(&log.JSONFormatter{})
	}

	if opts.ConfigFile == "" {
		opts.ConfigFile = "goplaned.conf"
	}

	configCh := make(chan config.ConfigSet)
	reloadCh := make(chan bool)
	go config.ReadConfigfileServe(opts.ConfigFile, configCh, reloadCh)
	reloadCh <- true
	bgpServer := bgpserver.NewBgpServer(bgp.BGP_PORT)
	go bgpServer.Serve()

	// start grpc Server
	grpcServer := bgpserver.NewGrpcServer(bgpserver.GRPC_PORT, bgpServer.GrpcReqCh)
	go grpcServer.Serve()

	var dataplane Dataplaner
	var bgpConfig *bgpconf.Bgp = nil
	var policyConfig *bgpconf.RoutingPolicy = nil

	for {
		select {
		case newConfig := <-configCh:
			var added []bgpconf.Neighbor
			var deleted []bgpconf.Neighbor

			if bgpConfig == nil {
				bgpServer.SetGlobalType(newConfig.Bgp.Global)
				bgpConfig = &newConfig.Bgp
				added = newConfig.Bgp.NeighborList
				deleted = []bgpconf.Neighbor{}
			} else {
				bgpConfig, added, deleted = bgpconf.UpdateConfig(bgpConfig, &newConfig.Bgp)
			}

			if policyConfig == nil {
				policyConfig = &newConfig.Policy
				bgpServer.SetPolicy(newConfig.Policy)
			} else {
				if res := bgpconf.CheckPolicyDifference(policyConfig, &newConfig.Policy); res {
					log.Info("Policy config is updated")
					bgpServer.UpdatePolicy(newConfig.Policy)
				}
			}

			if dataplane == nil {
				switch newConfig.Dataplane.Type {
				case "netlink":
					log.Debug("new dataplane: netlink")
					dataplane = netlink.NewDataplane(&newConfig)
					go func() {
						err := dataplane.Serve()
						if err != nil {
							log.Errorf("dataplane finished with err: %s", err)
						}
					}()
				default:
					log.Errorf("Invalid dataplane type(%s). dataplane engine can't be started", newConfig.Dataplane.Type)
				}
			} else {
				log.Debug("Dataplane config update is not supported yet")
			}

			for _, p := range added {
				log.Infof("Peer %v is added", p.NeighborAddress)
				bgpServer.PeerAdd(p)
			}
			for _, p := range deleted {
				log.Infof("Peer %v is deleted", p.NeighborAddress)
				bgpServer.PeerDelete(p)
			}
		case sig := <-sigCh:
			switch sig {
			case syscall.SIGHUP:
				log.Info("reload the config file")
				reloadCh <- true
			}
		}
	}
}