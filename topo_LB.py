#!/usr/bin/python3
import sys

"""
        C1              WS1
          \            /
           [s1]----[LB]
          /            \
        C2              WS2
"""

from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.node import OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from functools import partial

PUB_WS_IP  = "10.0.0.10"
PUB_WS_MAC = "00:11:22:33:44:55"

def createNet(controller_ip, controller_port):

    # Create an empty network and add nodes to it.
    switch = partial( OVSSwitch, protocols='OpenFlow13' )
    net = Mininet( controller=Controller, switch=switch )

    info( '*** Adding controller\n' )
    net.addController( 'c0', controller=RemoteController, ip=controller_ip, port=controller_port )

    info( '*** Adding hosts\n' )
    # c1 = net.addHost( 'C1' , ip= '10.0.0.1/24', defaultRoute = 'via 10.0.0.1')
    c1  = net.addHost( 'C1',  ip='10.0.0.1/24')
    c2  = net.addHost( 'C2',  ip='10.0.0.2/24')
    c3  = net.addHost( 'C3',  ip='10.0.0.3/24')
    ws1 = net.addHost( 'WS1', ip='10.0.0.11/24', mac='00:00:00:00:00:11')
    ws2 = net.addHost( 'WS2', ip='10.0.0.22/24', mac='00:00:00:00:00:22')

    info( '*** Adding switch\n' )
    s1 = net.addSwitch( 's1' )
    s2 = net.addSwitch( 's2' )

    info( '*** Creating links\n' )
    net.addLink(c1,s1)
    net.addLink(c2,s1)
    net.addLink(c3,s1)
    net.addLink(s1,s2)
    net.addLink(s2,ws1)
    net.addLink(s2,ws2)

    info( '*** Starting network\n')
    net.start()

    # create ARP entries
    info( '*** Adding ARP entries\n')
    c1.cmd("sudo arp -s " + PUB_WS_IP + " " + PUB_WS_MAC)
    c2.cmd("sudo arp -s " + PUB_WS_IP + " " + PUB_WS_MAC)
    c3.cmd("sudo arp -s " + PUB_WS_IP + " " + PUB_WS_MAC)
    ws1.cmd("sudo arp -s " + str(c1.IP()) + " " + str(c1.MAC()))
    ws1.cmd("sudo arp -s " + str(c2.IP()) + " " + str(c2.MAC()))
    ws1.cmd("sudo arp -s " + str(c3.IP()) + " " + str(c3.MAC()))
    ws2.cmd("sudo arp -s " + str(c1.IP()) + " " + str(c1.MAC()))
    ws2.cmd("sudo arp -s " + str(c2.IP()) + " " + str(c2.MAC()))
    ws2.cmd("sudo arp -s " + str(c3.IP()) + " " + str(c3.MAC()))

    # start web server on hosts WS1 and WS2
    # info( '*** Starting simple HTTP servers\n')
    # ws1.cmd( 'python -m SimpleHTTPServer 80 &' )
    # ws2.cmd( 'python -m SimpleHTTPServer 80 &' )

    # net.pingAll(timeout=1)

    info( '*** Running CLI\n' )
    CLI( net )

    info( '*** Stopping network' )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    if len(sys.argv) != 3:
        print('Usage: ', sys.argv[0], ' controller_ip controller_port')
        sys.exit()
    createNet(sys.argv[1], int(sys.argv[2]))
