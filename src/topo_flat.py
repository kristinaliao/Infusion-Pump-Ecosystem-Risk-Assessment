#!/usr/bin/env python3

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Controller
from mininet.cli import CLI
from mininet.log import setLogLevel, info

class FlatHospitalTopo(Topo):
    """
    A flat hospital network where all devices are on the same subnet (10.0.0.x).
    No internal firewalls or segmentation.
    """
    def build(self):
        # One central switch for everything
        s1 = self.addSwitch('s1')

        # Add Nodes
        attacker = self.addHost('attacker', ip='10.0.0.99/24')
        admin_pc = self.addHost('admin_pc', ip='10.0.0.10/24')
        med_gw = self.addHost('med_gw', ip='10.0.0.20/24')
        pump1 = self.addHost('pump1', ip='10.0.0.101/24')
        pump2 = self.addHost('pump2', ip='10.0.0.102/24')
        pump3 = self.addHost('pump3', ip='10.0.0.103/24')
        nursing_stn = self.addHost('nursing_stn', ip='10.0.0.30/24')

        # Connect everyone to the same switch
        for host in [attacker, admin_pc, med_gw, pump1, pump2, pump3, nursing_stn]:
            self.addLink(host, s1)

def run():
    setLogLevel('info')
    topo = FlatHospitalTopo()
    net = Mininet(topo=topo, controller=Controller)
    net.start()
    info('*** Flat Network Initialized. Everything is on 10.0.0.0/24\n')
    CLI(net)
    net.stop()

if __name__ == '__main__':
    run()
