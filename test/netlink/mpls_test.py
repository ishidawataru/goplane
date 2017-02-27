# Copyright (C) 2017 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import unittest
import nose
import os
import sys
import time
import logging
import json
from noseplugin import OptionParser
from base import *

class Test(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        c1 = Container(name='c1', image='osrg/gobgp')
        c2 = Container(name='c2', image='osrg/gobgp')
        pe1 = Container(name='pe1', image='osrg/gobgp')
        pe2 = Container(name='pe2', image='osrg/gobgp')
        p1 = Container(name='p1', image='osrg/gobgp')
        p2 = Container(name='p2', image='osrg/gobgp')

        ctns = [c1, c2, pe1, pe2, p1, p2]
        for c in ctns:
            c.shared_volumes = [('/home/vagrant', '/root')]
        [ctn.run() for ctn in ctns]

        br01 = Bridge(name='br01', subnet='192.168.10.0/24')
        br01.addif(c1)
        br01.addif(pe1)

        br02 = Bridge(name='br02', subnet='192.168.20.0/24')
        br02.addif(c2)
        br02.addif(pe2)

        br03 = Bridge(name='br03', subnet='192.168.30.0/24')
        br03.addif(pe1)
        br03.addif(p1)

        br04 = Bridge(name='br04', subnet='192.168.40.0/24')
        br04.addif(pe2)
        br04.addif(p1)

#        br05 = Bridge(name='br05', subnet='192.168.50.0/24')
#        br05.addif(pe1)
#        br05.addif(p2)
#
#        br06 = Bridge(name='br06', subnet='192.168.60.0/24')
#        br06.addif(pe2)
#        br06.addif(p2)

        [ctn.local('sysctl -w net.mpls.platform_labels=10000') for ctn in ctns]
        [[ctn.local('sysctl -w net.mpls.conf.{0}.input=1'.format(i[0])) for i in ctn.ip_addrs + [['lo']]] for ctn in ctns]

        cls.ctns = {ctn.name: ctn for ctn in ctns}

    def test_01_neighbor_established(self):
        ip = '/root/.ghq/git.kernel.org/pub/scm/linux/kernel/git/shemminger/iproute2/ip/ip'
        self.ctns['c1'].local('{0} r add 192.168.20.0/24 dev eth0 via 192.168.10.2'.format(ip))
        self.ctns['pe1'].local('{0} r add 192.168.20.0/24 encap mpls 100 dev eth1 via inet 192.168.30.2'.format(ip))
        self.ctns['p1'].local('{0} -f mpls r add 100 as to 200 dev eth1 via inet 192.168.40.1'.format(ip))
#        self.ctns['pe2'].local('{0} -f mpls r add 200 dev eth0 via inet 192.168.20.1'.format(ip))
        self.ctns['pe2'].local('{0} -f mpls r add 200 dev lo via inet 192.168.20.2'.format(ip))

        self.ctns['c2'].local('{0} r add 192.168.10.0/24 dev eth0 via 192.168.20.2'.format(ip))
        self.ctns['pe2'].local('{0} r add 192.168.10.0/24 encap mpls 300 dev eth1 via inet 192.168.40.2'.format(ip))
        self.ctns['p1'].local('{0} -f mpls r add 300 as to 400 dev eth0 via inet 192.168.30.1'.format(ip))
        self.ctns['pe1'].local('{0} -f mpls r add 400 dev eth0 via inet 192.168.10.1'.format(ip))

if __name__ == '__main__':
    if os.geteuid() is not 0:
        print "you are not root."
        sys.exit(1)
    logging.basicConfig(stream=sys.stderr)
    nose.main(argv=sys.argv, addplugins=[OptionParser()],
              defaultTest=sys.argv[0])
