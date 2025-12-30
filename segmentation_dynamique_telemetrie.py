# -*- coding: utf-8 -*-
"""
ZeroTrustDynamicSegmentation + télémétrie (Étape 3)

Fonctions ajoutées :
- Collecte périodique des stats de flows (packets/bytes) depuis le contrôleur
- Détection de nouveaux flows (par le contrôleur)
- Indicateur "scan" : fréquence/variété des ports TCP essayés par une même source
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
)
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, arp, ipv4, icmp, tcp
from ryu.lib import hub

import json
import time
from collections import deque, defaultdict


class ZeroTrustDynamicSegmentationTelemetry(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    H1 = "10.0.0.1"
    H2 = "10.0.0.2"
    H3 = "10.0.0.3"
    H4 = "10.0.0.4"

    # --- paramètres télémétrie ---
    STATS_INTERVAL_SEC = 5          # fréquence de poll des stats
    SCAN_WINDOW_SEC = 10            # fenêtre temps pour détecter "scan"
    SCAN_UNIQUE_PORTS_THRESHOLD = 8 # alerte si >= N ports différents dans la fenêtre

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # MAC learning
        self.mac_to_port = {}  # dpid -> {mac: port}

        # datapaths connectés (pour envoyer des FlowStatsRequest)
        self.datapaths = {}

        # suivi flows vus/connus + compteurs
        self.known_flow_keys = set()
        self.flow_counters = {}  # flow_key -> (packets, bytes)

        # indicateur scan : src_ip -> deque[(ts, dst_port)]
        self.port_history = defaultdict(lambda: deque())

        # thread de monitoring stats
        self.monitor_thread = hub.spawn(self._monitor)

    # -----------------------------
    # Helpers
    # -----------------------------
    def _flow_key(self, priority, match):
        """Clé stable pour identifier un flow (priorité + match JSON)."""
        try:
            m = match.to_jsondict()
        except Exception:
            m = str(match)
        return json.dumps({"p": priority, "m": m}, sort_keys=True)

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

        # Détection "nouveau flow" côté contrôleur
        key = self._flow_key(priority, match)
        if key not in self.known_flow_keys:
            self.known_flow_keys.add(key)
            self.logger.info("[NEW-FLOW] priority=%s match=%s", priority, match)

    # -----------------------------
    # Connexion / déconnexion switch
    # -----------------------------
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if dp.id not in self.datapaths:
                self.datapaths[dp.id] = dp
                self.logger.info("Datapath connected: dpid=%s", dp.id)
        elif ev.state == DEAD_DISPATCHER:
            if dp.id in self.datapaths:
                self.datapaths.pop(dp.id, None)
                self.logger.info("Datapath disconnected: dpid=%s", dp.id)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        # Table-miss: envoyer au contrôleur (obligatoire pour apprendre ports + appliquer politique)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, priority=0, match=match, actions=actions, idle_timeout=0, hard_timeout=0)

        self.logger.info("Controller ready: table-miss -> controller")

    # -----------------------------
    # Politique Zero Trust (segmentation)
    # -----------------------------
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

    # -----------------------------
    # Étape 3 — télémétrie
    # -----------------------------
    def _monitor(self):
        """Thread périodique : demande les stats de flows."""
        while True:
            try:
                for dp in list(self.datapaths.values()):
                    self._request_flow_stats(dp)
            except Exception as e:
                self.logger.error("Monitor error: %s", e)
            hub.sleep(self.STATS_INTERVAL_SEC)

    def _request_flow_stats(self, datapath):
        """Envoie une requête FlowStatsRequest au switch."""
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """Réception des stats : packets/bytes par flow + delta."""
        body = ev.msg.body
        dp = ev.msg.datapath

        # On affiche uniquement table=0 et priorité > 0 (on ignore table-miss)
        flows = [f for f in body if f.table_id == 0 and f.priority > 0]
        for stat in sorted(flows, key=lambda x: (x.priority, str(x.match))):
            key = self._flow_key(stat.priority, stat.match)

            # "nouveau flow" détecté par la télémétrie
            if key not in self.known_flow_keys:
                self.known_flow_keys.add(key)
                self.logger.info("[NEW-FLOW-STATS] dpid=%s priority=%s match=%s",
                                 dp.id, stat.priority, stat.match)

            prev = self.flow_counters.get(key, (0, 0))
            cur = (stat.packet_count, stat.byte_count)
            self.flow_counters[key] = cur

            d_pkts = cur[0] - prev[0]
            d_bytes = cur[1] - prev[1]

            # Log utile (uniquement si ça bouge)
            if d_pkts > 0 or d_bytes > 0:
                self.logger.info("[FLOW-STATS] dpid=%s match=%s packets=%s(+%s) bytes=%s(+%s)",
                                 dp.id, stat.match, cur[0], d_pkts, cur[1], d_bytes)

    def _update_scan_indicator(self, src_ip, dst_port):
        """Suivi de ports TCP essayés par une source (indicateur scan)."""
        now = time.time()
        q = self.port_history[src_ip]
        q.append((now, dst_port))

        # purge fenêtre
        while q and (now - q[0][0]) > self.SCAN_WINDOW_SEC:
            q.popleft()

        unique_ports = {p for (_, p) in q}
        if len(unique_ports) >= self.SCAN_UNIQUE_PORTS_THRESHOLD:
            self.logger.warning(
                "[SCAN?] src=%s tried %s unique TCP dst ports in last %ss: %s",
                src_ip, len(unique_ports), self.SCAN_WINDOW_SEC, sorted(unique_ports)
            )

    # -----------------------------
    # Packet-In : apprentissage + application politique
    # -----------------------------
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

        # Choix du port de sortie (si MAC connue)
        out_port = self.mac_to_port[dpid].get(eth.dst, ofp.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        # --- ARP ---
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            a = pkt.get_protocol(arp.arp)
            if a:
                if a.src_ip == self.H4 or a.dst_ip == self.H4:
                    self.logger.info("DROP ARP involving h4 (%s -> %s)", a.src_ip, a.dst_ip)
                    return

            out = parser.OFPPacketOut(
                datapath=dp,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
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

            # Layer4
            l4_tcp = pkt.get_protocol(tcp.tcp) if ip_proto == 6 else None
            l4_icmp = pkt.get_protocol(icmp.icmp) if ip_proto == 1 else None
            l4 = l4_tcp if l4_tcp else l4_icmp

            # Indicateur scan : on observe tous les TCP (même ceux qui seront drop)
            if l4_tcp is not None:
                self._update_scan_indicator(ip_src, l4_tcp.dst_port)

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
                elif ip_proto == 6 and l4_tcp is not None:
                    if l4_tcp.dst_port in {80, 443}:
                        match = parser.OFPMatch(
                            eth_type=0x0800,
                            ipv4_src=ip_src,
                            ipv4_dst=ip_dst,
                            ip_proto=6,
                            tcp_dst=l4_tcp.dst_port
                        )
                    else:
                        match = parser.OFPMatch(
                            eth_type=0x0800,
                            ipv4_src=ip_src,
                            ipv4_dst=ip_dst,
                            ip_proto=6,
                            tcp_src=l4_tcp.src_port
                        )
                else:
                    return

                self.add_flow(dp, priority=200, match=match, actions=actions, buffer_id=msg.buffer_id)

            out = parser.OFPPacketOut(
                datapath=dp,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
            )
            dp.send_msg(out)
            return

        return
