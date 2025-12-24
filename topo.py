#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Topo Mininet: 1 switch OVS (OpenFlow13) + 4 hôtes, reliés à un contrôleur Ryu.

Usage :
  1) Terminal A : ryu-manager zero_trust.py
  2) Terminal B : sudo python3 topo.py
  3) Dans Mininet : pingall, ou tests HTTP (voir la doc)

Par défaut, le contrôleur est en local (127.0.0.1:6633).
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info


def build_network(ctrl_ip="127.0.0.1", ctrl_port=6633):
    net = Mininet(controller=None, switch=OVSSwitch, build=False, autoSetMacs=True)

    info("*** Adding controller\n")
    c0 = net.addController(
        name="c0",
        controller=RemoteController,
        ip=ctrl_ip,
        port=ctrl_port
    )

    info("*** Adding switch (OpenFlow13)\n")
    s1 = net.addSwitch("s1", protocols="OpenFlow13")

    info("*** Adding hosts\n")
    h1 = net.addHost("h1", ip="10.0.0.1/24")
    h2 = net.addHost("h2", ip="10.0.0.2/24")
    h3 = net.addHost("h3", ip="10.0.0.3/24")
    h4 = net.addHost("h4", ip="10.0.0.4/24")

    info("*** Creating links\n")
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    net.addLink(h4, s1)

    info("*** Starting network\n")
    net.build()
    c0.start()
    s1.start([c0])

    return net


def main():
    setLogLevel("info")
    net = None
    try:
        net = build_network()
        info("*** Starting CLI (type 'exit' to stop)\n")
        CLI(net)
    finally:
        if net is not None:
            info("*** Stopping network\n")
            net.stop()


if __name__ == "__main__":
    main()
