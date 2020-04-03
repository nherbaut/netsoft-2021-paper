#!/usr/bin/python

from fattree import FatTree

import time

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Controller, OVSKernelSwitch, RemoteController
from mininet.link import TCLink
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.topo import *
from math import floor
from mininet import term


class SingleSwitchTopo(Topo):
    "Single switch connected to n hosts."

    def build(self, n=1):
        hosts = []
        switches = []
        for h in range(0, 12):
            host = self.addHost('h%s' % (h + 1), mac='00:00:00:00:00:%02d' % (h + 1))
            hosts.append(host)

        for s in range(0, 10):
            switch = self.addSwitch('s%s' % (s + 1))
            switches.append(switch)

        # access
        for h in range(0, 12):
            self.addLink(switches[h / 3], hosts[h])

        self.addLink(switches[0], switches[4])
        self.addLink(switches[0], switches[5])
        self.addLink(switches[1], switches[4])
        self.addLink(switches[1], switches[5])
        self.addLink(switches[2], switches[6])
        self.addLink(switches[2], switches[7])
        self.addLink(switches[3], switches[6])
        self.addLink(switches[4], switches[7])

        # aggregation
        self.addLink(switches[4], switches[5])
        self.addLink(switches[4], switches[8])
        self.addLink(switches[4], switches[9])

        self.addLink(switches[5], switches[4])
        self.addLink(switches[5], switches[8])
        self.addLink(switches[5], switches[9])

        self.addLink(switches[6], switches[7])
        self.addLink(switches[6], switches[8])
        self.addLink(switches[6], switches[9])

        self.addLink(switches[7], switches[6])
        self.addLink(switches[7], switches[8])
        self.addLink(switches[7], switches[9])

        # core
        self.addLink(switches[8], switches[9])


def simpleTest():
    "Create and test a simple network"
    topo = FatTree(6)
    net = Mininet(topo, controller=RemoteController, link=TCLink)
    net.start()
    print
    "Dumping host connections"
    dumpNodeConnections(net.hosts)
    print
    "Testing network connectivity"

    # ping_all_cmd = "fping -t 10 -l -p 5000 " + " ".join([host.IP() for host in net.hosts])+" > /tmp/%s_logs.txt &"
    # for host in net.hosts:
    #    host.cmd(ping_all_cmd%host.name)
    # print(dir(host))

    #    for host in net.hosts:
    #      term.makeTerm(host)

    while True:
        net.ping(timeout=20)
        time.sleep(6)

    net.stop()


if __name__ == '__main__':
    # Tell mininet to print useful information
    setLogLevel('info')
    simpleTest()
