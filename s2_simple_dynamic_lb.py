#
# Dynamic load balancer for topology topo_LB.py
# SDN OpenFlow lab - Université de Toulouse - France
#

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.ofproto import ofproto_v1_3

# Adresses IP et MAC des composants
PUB_WS_IP = '10.0.0.10'
PUB_WS_MAC = '00:11:22:33:44:55'

WS1_IP = '10.0.0.11'
WS1_MAC = '00:00:00:00:00:11'
WS2_IP = '10.0.0.22'
WS2_MAC = '00:00:00:00:00:22'

C1_IP = '10.0.0.1'
C2_IP = '10.0.0.2'

class DynamicLB(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DynamicLB, self).__init__(*args, **kwargs)
        # Dictionnaire pour garder la trace des serveurs actifs
        self.servers = {WS1_IP: WS1_MAC, WS2_IP: WS2_MAC}
        self.client_requests = {C1_IP: 0, C2_IP: 0}  # Compte les requêtes des clients

    @set_ev_cls(ofp_event.EventOFPStateChange, MAIN_DISPATCHER)
    def state_change_handler(self, ev):
        datapath = ev.datapath
        self.logger.info("Changement d'état pour le datapath: %s", datapath.id)
        # Ici, vous pouvez ajouter de la logique pour gérer l'activation/désactivation des serveurs.

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Ne contrôler que le switch S2
        if datapath.id != 2:
            return

        # Ajouter des règles pour chaque client
        self.add_load_balancing_rules(datapath)

    def add_load_balancing_rules(self, datapath):
        # Règles pour C1
        match_c1 = datapath.ofproto_parser.OFPMatch(
            in_port=1, eth_type=0x0800, ipv4_dst=PUB_WS_IP, ipv4_src=C1_IP
        )
        actions_c1 = self.select_server(C1_IP)  # Choisir le serveur pour C1
        self.add_flow(datapath, 1, match_c1, actions_c1)

        # Règles pour C2
        match_c2 = datapath.ofproto_parser.OFPMatch(
            in_port=1, eth_type=0x0800, ipv4_dst=PUB_WS_IP, ipv4_src=C2_IP
        )
        actions_c2 = self.select_server(C2_IP)  # Choisir le serveur pour C2
        self.add_flow(datapath, 1, match_c2, actions_c2)

    def select_server(self, client_ip):
        # Sélectionne un serveur basé sur un algorithme simple (ex. Round Robin)
        # Ici, nous pourrions aussi tenir compte des requêtes en cours ou des performances
        if self.client_requests[client_ip] % 2 == 0:
            self.client_requests[client_ip] += 1
            return [
                self.datapath.ofproto_parser.OFPActionSetField(eth_dst=WS1_MAC),
                self.datapath.ofproto_parser.OFPActionSetField(ipv4_dst=WS1_IP),
                self.datapath.ofproto_parser.OFPActionOutput(2)
            ]
        else:
            self.client_requests[client_ip] += 1
            return [
                self.datapath.ofproto_parser.OFPActionSetField(eth_dst=WS2_MAC),
                self.datapath.ofproto_parser.OFPActionSetField(ipv4_dst=WS2_IP),
                self.datapath.ofproto_parser.OFPActionOutput(3)
            ]

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
