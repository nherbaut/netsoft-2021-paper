#!/usr/bin/python                                                                         



import time

from fattree import FatTree
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

       
def simpleTest():
    "Create and test a simple network"
    topo = FatTree(4)
    net = Mininet(topo,controller=RemoteController,link=TCLink)
    net.start()
    print "Dumping host connections"
    dumpNodeConnections(net.hosts)
    print "Testing network connectivity"

    #ping_all_cmd = "fping -t 10 -l -p 5000 " + " ".join([host.IP() for host in net.hosts])+" > /tmp/%s_logs.txt &" 
    #for host in net.hosts:
    #    host.cmd(ping_all_cmd%host.name)
    #print(dir(host))

#    for host in net.hosts:
#      term.makeTerm(host)

    try:
      while True:
        net.ping(timeout=5)
        time.sleep(6)
    except KeyboardInterrupt:
      pass		
    CLI(net)
    net.stop()

if __name__ == '__main__':
    # Tell mininet to print useful information
    setLogLevel('info')
    simpleTest()

