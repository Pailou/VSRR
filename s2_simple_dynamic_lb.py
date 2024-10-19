#
# Dynamic load balancer for topology topo_LB.py
# SDN OpenFlow lab - Université de Toulouse - France
#

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4  # Importer le paquet IPv4

PUB_WS_IP  = '10.0.0.10'
PUB_WS_MAC = '00:11:22:33:44:55'

WS1_IP  = '10.0.0.11'
WS1_MAC = '00:00:00:00:00:11'
WS2_IP  = '10.0.0.22'
WS2_MAC = '00:00:00:00:00:22'

C1_IP = '10.0.0.1'
C2_IP = '10.0.0.2'

class DynamicLB(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DynamicLB, self).__init__(*args, **kwargs)
        self.token = 1  # Initialiser le token pour le round robin

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Control only S2
        if datapath.id != 2:
            return

        # Ajouter une règle par défaut pour renvoyer les paquets non traités vers le contrôleur
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)

        if eth_pkt and eth_pkt.ethertype == ether_types.ETH_TYPE_IP:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if ip_pkt is not None:
                src_ip = ip_pkt.src  # Récupérer l'adresse source IP
                dst_ip = ip_pkt.dst  # Récupérer l'adresse de destination IP

                # Logique de répartition
                if src_ip == C1_IP or src_ip == C2_IP:
                    # 1) Créer une correspondance pour le flux
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip)

                    if self.token == 1:
                        # 1) Ajouter une règle de relayage vers WS1
                        actions = [parser.OFPActionOutput(1)]  # Port vers WS1
                        # 2) Ajouter une règle de retour repositionnant l'adresse publique du serveur web
                        actions_return = [parser.OFPActionSetField(eth_dst=PUB_WS_MAC),
                                          parser.OFPActionOutput(in_port)]
                        # 3) Mettre à jour le token
                        self.token = 2
                    else:
                        # 1) Ajouter une règle de relayage vers WS2
                        actions = [parser.OFPActionOutput(2)]  # Port vers WS2
                        # 2) Ajouter une règle de retour repositionnant l'adresse publique du serveur web
                        actions_return = [parser.OFPActionSetField(eth_dst=PUB_WS_MAC),
                                          parser.OFPActionOutput(in_port)]
                        # 3) Mettre à jour le token
                        self.token = 1

                    # Ajouter la règle de flux avec idle_timeout
                    self.add_flow(datapath, 1, match, actions, idle_timeout=10)

                    # Ajouter la règle de retour
                    self.add_flow(datapath, 1, match, actions_return, idle_timeout=10)

                    # Réinjecter le paquet d'origine
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                               in_port=in_port, actions=actions)
                    datapath.send_msg(out)

    # Ajouter une entrée dans la table de flux
    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, idle_timeout=idle_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst, idle_timeout=idle_timeout)
        datapath.send_msg(mod)
