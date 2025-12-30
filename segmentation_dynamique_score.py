# -*- coding: utf-8 -*-
"""
Step 4 - Dynamic trust score (heuristic)

Signals that decrease trust:
- many different TCP destination ports in a short window (scan indicator)
- abnormal outgoing throughput (bytes/s) based on FlowStats deltas
- access to a non-allowed resource (policy DROP)

Optional:
- if trust < MIN_TRUST_TO_ALLOW, deny even normally-allowed traffic
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, arp, ipv4, icmp, tcp
from ryu.lib import hub

import time
import json
from collections import defaultdict, deque


class ZeroTrustDynamicSegmentationScore(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    H1 = "10.0.0.1"
    H2 = "10.0.0.2"
    H3 = "10.0.0.3"
    H4 = "10.0.0.4"

    # Telemetry poll interval
    STATS_INTERVAL_SEC = 5

    # Trust score settings
    TRUST_DEFAULT = 100
    TRUST_MIN = 0
    TRUST_MAX = 100
    MIN_TRUST_TO_ALLOW = 50  # if score < this, we deny traffic (revocation-like)

    # (1) Port scan indicator
    SCAN_WINDOW_SEC = 10
    SCAN_UNIQUE_PORTS_THRESHOLD = 8
    SCAN_PENALTY = 15
    SCAN_PENALTY_COOLDOWN_SEC = 10

    # (2) Abnormal outgoing throughput (bytes/s)
    OUT_BPS_THRESHOLD = 30000
    OUT_BPS_PENALTY = 20
    OUT_PENALTY_COOLDOWN_SEC = 5

    # (3) Access to non-allowed resource
    UNEXPECTED_ACCESS_PENALTY = 5
    UNEXPECTED_PENALTY_COOLDOWN_SEC = 2

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.mac_to_port = {}             # dpid -> {mac: port}
        self.datapaths = {}               # dpid -> datapath
        self.known_flow_keys = set()
        self.flow_counters = {}           # flow_key -> (packets, bytes)

        self.port_history = defaultdict(lambda: deque())  # src_ip -> deque[(ts, dst_port)]
        self.trust = defaultdict(lambda: self.TRUST_DEFAULT)

        # cooldowns
        self.last_scan_penalty = defaultdict(lambda: 0.0)
        self.last_out_penalty = defaultdict(lambda: 0.0)
        self.last_unexpected_penalty = defaultdict(lambda: 0.0)

        self.monitor_thread = hub.spawn(self._monitor)

    # -----------------------------
    # Trust helpers
    # -----------------------------
    def _clamp(self, v, lo, hi):
        return max(lo, min(hi, v))

    def penalize(self, src_ip, amount, reason):
        old = self.trust[src_ip]
        new = self._clamp(old - amount, self.TRUST_MIN, self.TRUST_MAX)
        if new != old:
            self.trust[src_ip] = new
            self.logger.warning("[TRUST] %s: %s -> %s (-%s) reason=%s",
                                src_ip, old, new, amount, reason)

    # -----------------------------
    # Flow helpers
    # -----------------------------
    def _flow_key(self, priority, match):
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

        datapath.send_msg(parser.OFPFlowMod(**kwargs))

        key = self._flow_key(priority, match)
        if key not in self.known_flow_keys:
            self.known_flow_keys.add(key)
            self.logger.info("[NEW-FLOW] priority=%s match=%s", priority, match)

    # -----------------------------
    # Switch tracking
    # -----------------------------
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
            self.logger.info("Datapath connected: dpid=%s", dp.id)
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(dp.id, None)
            self.logger.info("Datapath disconnected: dpid=%s", dp.id)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        # table-miss -> controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, priority=0, match=match, actions=actions, idle_timeout=0, hard_timeout=0)
        self.logger.info("Controller ready: table-miss -> controller")

    # -----------------------------
    # Policy + trust gate
    # -----------------------------
    def is_blocked_by_policy(self, ip_src, ip_dst):
        return (ip_src == self.H4) or (ip_dst == self.H4)

    def is_allowed_ipv4(self, ip_src, ip_dst, ip_proto, l4):
        # hard block h4
        if self.is_blocked_by_policy(ip_src, ip_dst):
            return False

        # trust gate
        if self.trust[ip_src] < self.MIN_TRUST_TO_ALLOW:
            return False

        # ICMP allowed between h1/h2/h3
        if ip_proto == 1:
            allowed_set = {self.H1, self.H2, self.H3}
            return (ip_src in allowed_set) and (ip_dst in allowed_set)

        # TCP 80/443: h1/h2 -> h3 and return h3 -> h1/h2
        if ip_proto == 6 and isinstance(l4, tcp.tcp):
            if ip_dst == self.H3 and ip_src in {self.H1, self.H2} and l4.dst_port in {80, 443}:
                return True
            if ip_src == self.H3 and ip_dst in {self.H1, self.H2} and l4.src_port in {80, 443}:
                return True
            return False

        return False

    # -----------------------------
    # Step 4 signals
    # -----------------------------
    def _update_scan_indicator(self, src_ip, dst_port):
        now = time.time()
        q = self.port_history[src_ip]
        q.append((now, dst_port))

        while q and (now - q[0][0]) > self.SCAN_WINDOW_SEC:
            q.popleft()

        unique_ports = {p for (_, p) in q}
        if len(unique_ports) >= self.SCAN_UNIQUE_PORTS_THRESHOLD:
            self.logger.warning("[SCAN?] src=%s tried %s unique TCP dst ports in last %ss: %s",
                                src_ip, len(unique_ports), self.SCAN_WINDOW_SEC, sorted(unique_ports))

            if (now - self.last_scan_penalty[src_ip]) >= self.SCAN_PENALTY_COOLDOWN_SEC:
                self.penalize(src_ip, self.SCAN_PENALTY, "port-scan-indicator")
                self.last_scan_penalty[src_ip] = now

    # -----------------------------
    # FlowStats polling + throughput scoring
    # -----------------------------
    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                self._request_flow_stats(dp)
            hub.sleep(self.STATS_INTERVAL_SEC)

    def _request_flow_stats(self, datapath):
        parser = datapath.ofproto_parser
        datapath.send_msg(parser.OFPFlowStatsRequest(datapath))

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        now = time.time()

        out_delta_bytes_by_src = defaultdict(int)

        flows = [f for f in body if f.table_id == 0 and f.priority > 0]
        for stat in flows:
            key = self._flow_key(stat.priority, stat.match)
            prev = self.flow_counters.get(key, (0, 0))
            cur = (stat.packet_count, stat.byte_count)
            self.flow_counters[key] = cur

            d_bytes = cur[1] - prev[1]
            if d_bytes <= 0:
                continue

            ip_src = stat.match.get("ipv4_src")
            if ip_src:
                out_delta_bytes_by_src[ip_src] += d_bytes

        for src_ip, d_bytes in out_delta_bytes_by_src.items():
            out_bps = int(d_bytes / max(1, self.STATS_INTERVAL_SEC))
            if out_bps >= self.OUT_BPS_THRESHOLD:
                self.logger.warning("[OUT-THROUGHPUT?] src=%s approx_out=%s B/s (threshold=%s)",
                                    src_ip, out_bps, self.OUT_BPS_THRESHOLD)

                if (now - self.last_out_penalty[src_ip]) >= self.OUT_PENALTY_COOLDOWN_SEC:
                    self.penalize(src_ip, self.OUT_BPS_PENALTY, "abnormal-outgoing-throughput")
                    self.last_out_penalty[src_ip] = now

    # -----------------------------
    # Packet-In
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
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # MAC learning
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port

        out_port = self.mac_to_port[dpid].get(eth.dst, ofp.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        # ARP: allow except h4
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            a = pkt.get_protocol(arp.arp)
            if a and (a.src_ip == self.H4 or a.dst_ip == self.H4):
                return
            dp.send_msg(parser.OFPPacketOut(
                datapath=dp,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
            ))
            return

        # IPv4: policy + trust
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip = pkt.get_protocol(ipv4.ipv4)
            if not ip:
                return

            ip_src = ip.src
            ip_dst = ip.dst
            ip_proto = ip.proto

            l4_tcp = pkt.get_protocol(tcp.tcp) if ip_proto == 6 else None
            l4_icmp = pkt.get_protocol(icmp.icmp) if ip_proto == 1 else None
            l4 = l4_tcp if l4_tcp else l4_icmp

            # scan indicator (even if later dropped)
            if l4_tcp is not None:
                self._update_scan_indicator(ip_src, l4_tcp.dst_port)

            allowed = self.is_allowed_ipv4(ip_src, ip_dst, ip_proto, l4)
            if not allowed:
                now = time.time()
                if (now - self.last_unexpected_penalty[ip_src]) >= self.UNEXPECTED_PENALTY_COOLDOWN_SEC:
                    self.penalize(ip_src, self.UNEXPECTED_ACCESS_PENALTY, "unexpected-access")
                    self.last_unexpected_penalty[ip_src] = now
                self.logger.info("DROP IPv4 %s -> %s proto=%s (trust=%s)",
                                 ip_src, ip_dst, ip_proto, self.trust[ip_src])
                return

            # install dynamic flow if dst MAC known
            if out_port != ofp.OFPP_FLOOD:
                if ip_proto == 1:
                    match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_src, ipv4_dst=ip_dst, ip_proto=1)
                elif ip_proto == 6 and l4_tcp is not None:
                    if l4_tcp.dst_port in {80, 443}:
                        match = parser.OFPMatch(
                            eth_type=0x0800, ipv4_src=ip_src, ipv4_dst=ip_dst, ip_proto=6, tcp_dst=l4_tcp.dst_port
                        )
                    else:
                        match = parser.OFPMatch(
                            eth_type=0x0800, ipv4_src=ip_src, ipv4_dst=ip_dst, ip_proto=6, tcp_src=l4_tcp.src_port
                        )
                else:
                    return

                self.add_flow(dp, priority=200, match=match, actions=actions, buffer_id=msg.buffer_id)

            dp.send_msg(parser.OFPPacketOut(
                datapath=dp,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
            ))
            return

        return
