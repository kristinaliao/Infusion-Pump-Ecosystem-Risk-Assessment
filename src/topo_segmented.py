#!/usr/bin/env python3

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Controller, Node
from mininet.cli import CLI
from mininet.log import setLogLevel, info

class LinuxRouter(Node):
    def config(self, **params):
        super(LinuxRouter, self).config(**params)
        self.cmd('sysctl net.ipv4.ip_forward=1')
    def terminate(self):
        self.cmd('sysctl net.ipv4.ip_forward=0')
        super(LinuxRouter, self).terminate()

class SegmentedHospitalTopo(Topo):
    """
    A segmented hospital network with three zones:
    1. External/Public (10.0.0.x)
    2. Enterprise/Admin (10.0.1.x)
    3. Medical IoT (10.0.2.x)
    """
    def build(self):
        # Border Router / Firewall
        r1 = self.addNode('r1', cls=LinuxRouter, ip='10.0.0.1/24')

        # Switches for each zone
        s_ent = self.addSwitch('s_ent')
        s_med = self.addSwitch('s_med')

        # Connect Router to Switches
        # eth1 -> Enterprise (10.0.1.1)
        self.addLink(s_ent, r1, intfName2='r1-eth1', params2={'ip': '10.0.1.1/24'})
        # eth2 -> Medical (10.0.2.1)
        self.addLink(s_med, r1, intfName2='r1-eth2', params2={'ip': '10.0.2.1/24'})

        # Zone 1: External (Attacker)
        # Connected directly to r1-eth0 (default ip 10.0.0.1)
        attacker = self.addHost('attacker', ip='10.0.0.99/24', defaultRoute='via 10.0.0.1')
        s_ext = self.addSwitch('s_ext')
        self.addLink(attacker, s_ext)
        self.addLink(s_ext, r1) # r1-eth0

        # Zone 2: Enterprise (Admin & Nursing)
        admin_pc = self.addHost('admin_pc', ip='10.0.1.10/24', defaultRoute='via 10.0.1.1')
        nursing_stn = self.addHost('nursing_stn', ip='10.0.1.30/24', defaultRoute='via 10.0.1.1')
        self.addLink(admin_pc, s_ent)
        self.addLink(nursing_stn, s_ent)

        # Zone 3: Medical IoT (Gateway & Pumps)
        med_gw = self.addHost('med_gw', ip='10.0.2.10/24', defaultRoute='via 10.0.2.1')
        pump1 = self.addHost('pump1', ip='10.0.2.101/24', defaultRoute='via 10.0.2.1')
        pump2 = self.addHost('pump2', ip='10.0.2.102/24', defaultRoute='via 10.0.2.1')
        pump3 = self.addHost('pump3', ip='10.0.2.103/24', defaultRoute='via 10.0.2.1')
        self.addLink(med_gw, s_med)
        self.addLink(pump1, s_med)
        self.addLink(pump2, s_med)
        self.addLink(pump3, s_med)

def run():
    setLogLevel('info')
    topo = SegmentedHospitalTopo()
    net = Mininet(topo=topo, controller=Controller)
    net.start()
    info('*** Segmented Network Initialized.\n')
    info('*** Zones: External (10.0.0.x), Enterprise (10.0.1.x), Medical (10.0.2.x)\n')
    CLI(net)
    net.stop()

if __name__ == '__main__':
    run()
