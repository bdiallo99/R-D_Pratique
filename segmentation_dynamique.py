# -*- coding: utf-8 -*-

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, arp, ipv4, icmp, tcp


class ZeroTrustDynamicSegmentation(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    H1 = "10.0.0.1"
    H2 = "10.0.0.2"
    H3 = "10.0.0.3"
    H4 = "10.0.0.4"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = {}  # dpid -> {mac: port}

    def add_flow(self, datapath, priority, match, actions,
                 idle_timeout=60, hard_timeout=0, buffer_id=None):
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        kwargs = dict(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout
        )
        if buffer_id is not None and buffer_id != ofp.OFP_NO_BUFFER:
            kwargs["buffer_id"] = buffer_id

        mod = parser.OFPFlowMod(**kwargs)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        # Table-miss: envoyer au contrôleur (sinon on ne peut pas apprendre dynamiquement)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, priority=0, match=match, actions=actions, idle_timeout=0, hard_timeout=0)

        self.logger.info("Controller ready: table-miss -> controller")

    def is_blocked_by_policy(self, ip_src, ip_dst):
        # Tout ce qui implique h4 est interdit
        return (ip_src == self.H4) or (ip_dst == self.H4)

    def is_allowed_ipv4(self, ip_src, ip_dst, ip_proto, l4):
        # Bloquer h4
        if self.is_blocked_by_policy(ip_src, ip_dst):
            return False

        # ICMP autorisé entre h1/h2/h3 (ping)
        if ip_proto == 1:  # ICMP
            allowed_set = {self.H1, self.H2, self.H3}
            return (ip_src in allowed_set) and (ip_dst in allowed_set)

        # TCP 80/443 : h1/h2 -> h3 + retours h3 -> h1/h2
        if ip_proto == 6 and isinstance(l4, tcp.tcp):
            # client -> serveur
            if ip_dst == self.H3 and ip_src in {self.H1, self.H2} and l4.dst_port in {80, 443}:
                return True
            # serveur -> client (réponses)
            if ip_src == self.H3 and ip_dst in {self.H1, self.H2} and l4.src_port in {80, 443}:
                return True
            return False

        # Tout le reste interdit
        return False

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        dpid = dp.id

        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None:
            return

        # Ignore LLDP
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # MAC learning (ports dynamiques)
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port

        # Choix du port de sortie
        out_port = self.mac_to_port[dpid].get(eth.dst, ofp.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        # --- ARP ---
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            a = pkt.get_protocol(arp.arp)
            if a:
                # Bloquer ARP si h4 est impliqué
                if a.src_ip == self.H4 or a.dst_ip == self.H4:
                    self.logger.info("DROP ARP involving h4 (%s -> %s)", a.src_ip, a.dst_ip)
                    return

            # ARP autorisé (flood si dst inconnu)
            out = parser.OFPPacketOut(
                datapath=dp, buffer_id=msg.buffer_id,
                in_port=in_port, actions=actions,
                data=msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
            )
            dp.send_msg(out)
            return

        # --- IPv4 ---
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip = pkt.get_protocol(ipv4.ipv4)
            if not ip:
                return

            ip_src = ip.src
            ip_dst = ip.dst
            ip_proto = ip.proto

            l4 = pkt.get_protocol(tcp.tcp) if ip_proto == 6 else pkt.get_protocol(icmp.icmp)

            allowed = self.is_allowed_ipv4(ip_src, ip_dst, ip_proto, l4)
            if not allowed:
                self.logger.info("DROP IPv4 %s -> %s proto=%s", ip_src, ip_dst, ip_proto)
                return

            # Si destination connue, on installe une règle (flow) dynamique
            if out_port != ofp.OFPP_FLOOD:
                if ip_proto == 1:  # ICMP
                    match = parser.OFPMatch(
                        eth_type=0x0800,
                        ipv4_src=ip_src,
                        ipv4_dst=ip_dst,
                        ip_proto=1
                    )
                elif ip_proto == 6 and isinstance(l4, tcp.tcp):
                    # On matche selon sens (dst_port ou src_port)
                    if l4.dst_port in {80, 443}:
                        match = parser.OFPMatch(
                            eth_type=0x0800,
                            ipv4_src=ip_src,
                            ipv4_dst=ip_dst,
                            ip_proto=6,
                            tcp_dst=l4.dst_port
                        )
                    else:
                        match = parser.OFPMatch(
                            eth_type=0x0800,
                            ipv4_src=ip_src,
                            ipv4_dst=ip_dst,
                            ip_proto=6,
                            tcp_src=l4.src_port
                        )
                else:
                    # Par sécurité
                    return

                self.add_flow(dp, priority=200, match=match, actions=actions, buffer_id=msg.buffer_id)

            # Forward le paquet
            out = parser.OFPPacketOut(
                datapath=dp, buffer_id=msg.buffer_id,
                in_port=in_port, actions=actions,
                data=msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
            )
            dp.send_msg(out)
            return

        # Tout le reste : drop (par défaut)
        return
