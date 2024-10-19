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
        self.servers = {WS1_IP: WS1_MAC, WS2_IP: WS2_MAC}
        self.client_requests = {C1_IP: None, C2_IP: None}

    @set_ev_cls(ofp_event.EventOFPStateChange, MAIN_DISPATCHER)
    def state_change_handler(self, ev):
        datapath = ev.datapath  # Correctement obtenir le datapath
        self.logger.info("State change for datapath: %s", datapath.id)

        # Logique pour gérer le changement d'état des serveurs
        # (ajoutez ici votre logique pour activer ou désactiver des serveurs)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Control only S2
        if datapath.id != 2:
            return

        # Ajouter des règles pour C1 ---> WS1
        match1 = parser.OFPMatch(
            in_port=1, eth_type=0x0800, ipv4_dst=PUB_WS_IP, ipv4_src=C1_IP
        )
        actions1 = [
            parser.OFPActionSetField(eth_dst=WS1_MAC),
            parser.OFPActionSetField(ipv4_dst=WS1_IP),
            parser.OFPActionOutput(2)
        ]
        self.add_flow(datapath, 1, match1, actions1)
        
        # Ajouter des règles pour WS1 ---> C1
        match2 = parser.OFPMatch(
            in_port=2, eth_type=0x0800, ipv4_src=WS1_IP, ipv4_dst=C1_IP
        )
        actions2 = [
            parser.OFPActionSetField(eth_src=PUB_WS_MAC),
            parser.OFPActionSetField(ipv4_src=PUB_WS_IP),
            parser.OFPActionOutput(1)
        ]
        self.add_flow(datapath, 1, match2, actions2)

        # Ajouter des règles pour C2 ---> WS2
        match3 = parser.OFPMatch(
            in_port=1, eth_type=0x0800, ipv4_dst=PUB_WS_IP, ipv4_src=C2_IP
        )
        actions3 = [
            parser.OFPActionSetField(eth_dst=WS2_MAC),
            parser.OFPActionSetField(ipv4_dst=WS2_IP),
            parser.OFPActionOutput(3)
        ]
        self.add_flow(datapath, 1, match3, actions3)

        # Ajouter des règles pour WS2 ---> C2
        match4 = parser.OFPMatch(
            in_port=3, eth_type=0x0800, ipv4_src=WS2_IP, ipv4_dst=C2_IP
        )
        actions4 = [
            parser.OFPActionSetField(eth_src=PUB_WS_MAC),
            parser.OFPActionSetField(ipv4_src=PUB_WS_IP),
            parser.OFPActionOutput(1)
        ]
        self.add_flow(datapath, 1, match4, actions4)

    # Ajouter une entrée (instruction appliquer des actions) dans la table de flux 0  
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
