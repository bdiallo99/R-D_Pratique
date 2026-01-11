from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp, udp, icmp
from ryu.lib import hub
from ryu.topology import event as topo_event
from ryu.topology.api import get_switch, get_link
import time
import json
from collections import defaultdict
from datetime import datetime
import threading
import random


class ZeroTrustSDNController(app_manager.RyuApp):
    """
    Contrôleur SDN Zero Trust avec révocation de session en temps réel
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(ZeroTrustSDNController, self).__init__(*args, **kwargs)
        
        # Tables de données Zero Trust
        self.mac_to_port = {}
        self.datapaths = {}
        
        # Profils utilisateurs/appareils authentifiés
        self.authenticated_devices = {
            '00:00:00:00:00:01': {'user': 'alice', 'role': 'admin', 'trust_score': 100, 'authenticated_at': time.time()},
            '00:00:00:00:00:02': {'user': 'bob', 'role': 'user', 'trust_score': 100, 'authenticated_at': time.time()},
            '00:00:00:00:00:03': {'user': 'charlie', 'role': 'user', 'trust_score': 100, 'authenticated_at': time.time()},
            '00:00:00:00:00:04': {'user': 'dave', 'role': 'guest', 'trust_score': 100, 'authenticated_at': time.time()},
        }
        
        # Politiques Zero Trust par rôle
        self.role_policies = {
            'admin': {
                'allowed_ports': [22, 80, 443, 3306, 8080],
                'max_bandwidth': 1000000,  # bytes/sec
                'allowed_protocols': ['TCP', 'UDP', 'ICMP'],
                'trust_threshold': 50
            },
            'user': {
                'allowed_ports': [80, 443, 8080],
                'max_bandwidth': 500000,
                'allowed_protocols': ['TCP', 'UDP'],
                'trust_threshold': 60
            },
            'guest': {
                'allowed_ports': [80, 443],
                'max_bandwidth': 100000,
                'allowed_protocols': ['TCP'],
                'trust_threshold': 70
            }
        }
        
        # Monitoring continu - métriques par appareil
        self.device_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'flow_count': 0,
            'last_seen': time.time(),
            'suspicious_behaviors': [],
            'port_scan_attempts': 0,
            'failed_connections': 0,
            'data_exfiltration_score': 0,
            'lateral_movement_score': 0
        })
        
        # Sessions actives avec timestamp
        self.active_sessions = {}
        
        # Liste des appareils révoqués
        self.revoked_devices = set()
        
        # Logs de sécurité
        self.security_logs = []
        
        # Thread de monitoring continu
        self.monitor_thread = hub.spawn(self._continuous_monitoring)
        
        # Thread d'analyse comportementale
        self.behavior_thread = hub.spawn(self._behavioral_analysis)
        
        self.logger.info("=== Contrôleur Zero Trust SDN initialisé ===")
        self.logger.info("Révocation dynamique activée")
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Installation des règles par défaut (table-miss flow entry)"""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        self.datapaths[datapath.id] = datapath
        
        # Installation de la règle table-miss
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        
        self.logger.info(f"Switch {datapath.id} connecté - règles Zero Trust prêtes")
    
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        """Gestion des changements d'état des switches"""
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.datapaths[datapath.id] = datapath
                self.logger.info(f"Switch {datapath.id} enregistré")
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]
                self.logger.info(f"Switch {datapath.id} déconnecté")
    
    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0, buffer_id=None):
        """Ajout d'une règle de flux OpenFlow"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,
                                    idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout)
        datapath.send_msg(mod)
    
    def delete_flow(self, datapath, match):
        """Suppression d'une règle de flux (pour révocation)"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=match
        )
        datapath.send_msg(mod)
        self.logger.info(f"Flux supprimé pour révocation : {match}")
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        Gestion des paquets entrants - Vérification Zero Trust par requête
        """
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        
        # Ignorer les paquets LLDP
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        
        # Mise à jour de la table MAC
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port
        
        # === VÉRIFICATION ZERO TRUST ===
        
        # 1. Vérifier si l'appareil source est authentifié
        if src not in self.authenticated_devices:
            self.logger.warning(f"Appareil NON AUTHENTIFIÉ détecté : {src}")
            self._log_security_event('UNAUTHENTICATED_DEVICE', src, {'port': in_port})
            return  # Bloquer le paquet
        
        # 2. Vérifier si l'appareil est révoqué
        if src in self.revoked_devices:
            self.logger.warning(f" Appareil RÉVOQUÉ tenté d'accéder : {src}")
            self._log_security_event('REVOKED_DEVICE_ACCESS', src, {'port': in_port})
            return  # Bloquer le paquet
        
        # 3. Vérification du score de confiance
        device_info = self.authenticated_devices[src]
        trust_score = device_info['trust_score']
        role = device_info['role']
        policy = self.role_policies[role]
        
        if trust_score < policy['trust_threshold']:
            self.logger.warning(f"  Score de confiance insuffisant pour {src} ({device_info['user']}): {trust_score} < {policy['trust_threshold']}")
            self._revoke_device_access(src, "Trust score below threshold")
            return
        
        # 4. Analyse du paquet pour détection d'anomalies
        anomaly_detected = self._analyze_packet_for_anomalies(pkt, src, dst, device_info)
        
        if anomaly_detected:
            self.logger.warning(f" ANOMALIE DÉTECTÉE pour {src} ({device_info['user']})")
            # Décrémenter le score de confiance
            self._decrease_trust_score(src, 10)
            
            # Si le score devient trop bas, révoquer
            if device_info['trust_score'] < policy['trust_threshold']:
                self._revoke_device_access(src, "Anomalous behavior detected")
                return
        
        # 5. Mise à jour des statistiques
        self._update_device_stats(src, len(msg.data))
        
        # 6. Apprentissage de la destination
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        
        actions = [parser.OFPActionOutput(out_port)]
        
        # Installation d'un flux temporaire avec timeout court (Zero Trust = per-request verification)
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # Timeout court pour forcer la revérification

            self.add_flow(datapath, 1, match, actions, idle_timeout=10, hard_timeout=30)
        
        # Envoi du paquet
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                   in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
    
    def _analyze_packet_for_anomalies(self, pkt, src, dst, device_info):
        """
        Analyse comportementale du paquet pour détecter des anomalies
        Retourne True si une anomalie est détectée
        """
        anomaly = False
        role = device_info['role']
        policy = self.role_policies[role]
        
        # Vérification des protocoles autorisés
        if pkt.get_protocol(ipv4.ipv4):
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            
            # Détection de scan de ports (TCP)
            if pkt.get_protocol(tcp.tcp):
                tcp_pkt = pkt.get_protocol(tcp.tcp)
                
                # Vérifier si le port de destination est autorisé
                if tcp_pkt.dst_port not in policy['allowed_ports']:
                    self.logger.warning(f"Port non autorisé : {tcp_pkt.dst_port} pour {src}")
                    self.device_stats[src]['suspicious_behaviors'].append({
                        'type': 'UNAUTHORIZED_PORT',
                        'port': tcp_pkt.dst_port,
                        'timestamp': time.time()
                    })
                    anomaly = True
                
                # Détection de scan de ports
                self.device_stats[src]['port_scan_attempts'] += 1
                if self.device_stats[src]['port_scan_attempts'] > 50:
                    self.logger.warning(f"Scan de ports détecté : {src}")
                    self.device_stats[src]['suspicious_behaviors'].append({
                        'type': 'PORT_SCAN',
                        'count': self.device_stats[src]['port_scan_attempts'],
                        'timestamp': time.time()
                    })
                    anomaly = True
            
            # Détection UDP (si non autorisé)
            if pkt.get_protocol(udp.udp):
                if 'UDP' not in policy['allowed_protocols']:
                    self.logger.warning(f"Protocole UDP non autorisé pour {src}")
                    anomaly = True
            
            # Détection ICMP (si non autorisé)
            if pkt.get_protocol(icmp.icmp):
                if 'ICMP' not in policy['allowed_protocols']:
                    self.logger.warning(f"Protocole ICMP non autorisé pour {src}")
                    anomaly = True
        
        return anomaly
    
    def _update_device_stats(self, mac, byte_count):
        """Mise à jour des statistiques d'un appareil"""
        stats = self.device_stats[mac]
        stats['packet_count'] += 1
        stats['byte_count'] += byte_count
        stats['last_seen'] = time.time()
    
    def _decrease_trust_score(self, mac, amount):
        """Diminution du score de confiance"""
        if mac in self.authenticated_devices:
            old_score = self.authenticated_devices[mac]['trust_score']
            self.authenticated_devices[mac]['trust_score'] = max(0, old_score - amount)
            new_score = self.authenticated_devices[mac]['trust_score']
            self.logger.info(f"Score de confiance {mac}: {old_score} -> {new_score}")
    
    def _revoke_device_access(self, mac, reason):
        """
        RÉVOCATION IMMÉDIATE de l'accès d'un appareil suspect
        """
        if mac in self.revoked_devices:
            return  # Déjà révoqué
        
        self.logger.critical(f"RÉVOCATION D'ACCÈS : {mac} ({self.authenticated_devices[mac]['user']})")
        self.logger.critical(f"   Raison : {reason}")
        
        # Marquer comme révoqué
        self.revoked_devices.add(mac)
        self.authenticated_devices[mac]['trust_score'] = 0
        
        # Supprimer TOUS les flux associés à cet appareil
        for dpid, datapath in self.datapaths.items():
            parser = datapath.ofproto_parser
            
            # Supprimer les flux avec src = mac
            match_src = parser.OFPMatch(eth_src=mac)
            self.delete_flow(datapath, match_src)
            
            # Supprimer les flux avec dst = mac
            match_dst = parser.OFPMatch(eth_dst=mac)
            self.delete_flow(datapath, match_dst)
        
        # Log de sécurité
        self._log_security_event('ACCESS_REVOKED', mac, {
            'reason': reason,
            'user': self.authenticated_devices[mac]['user'],
            'role': self.authenticated_devices[mac]['role'],
            'trust_score': self.authenticated_devices[mac]['trust_score']
        })
        
        self.logger.critical(f"Révocation complétée pour {mac}")
    
    def _continuous_monitoring(self):
        """
        Thread de monitoring continu - Vérification périodique des appareils
        """
        while True:
            hub.sleep(5)  # Vérification toutes les 5 secondes
            
            current_time = time.time()
            
            for mac, device_info in list(self.authenticated_devices.items()):
                if mac in self.revoked_devices:
                    continue
                
                stats = self.device_stats[mac]
                
                # Détection d'inactivité suspecte après authentification
                time_since_auth = current_time - device_info['authenticated_at']
                time_since_seen = current_time - stats['last_seen']
                
                # Détection de comportements suspects accumulés
                if len(stats['suspicious_behaviors']) > 5:
                    self.logger.warning(f"Trop de comportements suspects pour {mac}")
                    self._decrease_trust_score(mac, 20)
                
                # Vérifier si révocation nécessaire
                role = device_info['role']
                threshold = self.role_policies[role]['trust_threshold']
                
                if device_info['trust_score'] < threshold:
                    self._revoke_device_access(mac, "Trust score dropped below threshold during monitoring")
    
    def _behavioral_analysis(self):
        """
        Thread d'analyse comportementale avancée
        Détection de patterns d'attaque sophistiqués
        """
        while True:
            hub.sleep(10)  # Analyse toutes les 10 secondes
            
            for mac, stats in list(self.device_stats.items()):
                if mac in self.revoked_devices:
                    continue
                
                # Détection de mouvement latéral
                # (Simulation : si trop de connexions vers différentes destinations)
                if stats['flow_count'] > 100:
                    stats['lateral_movement_score'] += 10
                    self.logger.warning(f"Mouvement latéral suspect : {mac}")
                    self._decrease_trust_score(mac, 15)
                
                # Détection d'exfiltration de données
                # (Simulation : si trop de données envoyées)
                if stats['byte_count'] > 10000000:  # 10 MB
                    stats['data_exfiltration_score'] += 10
                    self.logger.warning(f"Exfiltration de données suspecte : {mac}")
                    self._decrease_trust_score(mac, 20)
                
                # Reset des compteurs
                stats['flow_count'] = 0
    
    def _log_security_event(self, event_type, mac, details):
        """Enregistrement des événements de sécurité"""
        event = {
            'timestamp': datetime.now().isoformat(),
            'type': event_type,
            'mac': mac,
            'user': self.authenticated_devices.get(mac, {}).get('user', 'UNKNOWN'),
            'details': details
        }
        self.security_logs.append(event)
        
        # Sauvegarder les logs
        try:
            with open('logs/security_logs.json', 'w') as f:
                json.dump(self.security_logs, f, indent=2)
        except Exception as e:
            self.logger.error(f"Erreur d'écriture des logs : {e}")
    
    def get_security_report(self):
        """Génération d'un rapport de sécurité"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'authenticated_devices': len(self.authenticated_devices),
            'revoked_devices': len(self.revoked_devices),
            'active_sessions': len(self.active_sessions),
            'security_events': len(self.security_logs),
            'device_details': []
        }
        
        for mac, device_info in self.authenticated_devices.items():
            stats = self.device_stats[mac]
            report['device_details'].append({
                'mac': mac,
                'user': device_info['user'],
                'role': device_info['role'],
                'trust_score': device_info['trust_score'],
                'is_revoked': mac in self.revoked_devices,
                'packet_count': stats['packet_count'],
                'byte_count': stats['byte_count'],
                'suspicious_behaviors': len(stats['suspicious_behaviors'])
            })
        
        return report
