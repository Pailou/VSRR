#
# Static load balancer for topology topo_LB.py
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

PUB_WS_IP  = '10.0.0.10'
PUB_WS_MAC = '00:11:22:33:44:55'

WS1_IP  = '10.0.0.11'
WS1_MAC = '00:00:00:00:00:11'
WS2_IP  = '10.0.0.22'
WS2_MAC = '00:00:00:00:00:22'

C1_IP = '10.0.0.1'
C2_IP = '10.0.0.2'

class SimpleLB(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleLB, self).__init__(*args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Control only S2
        if datapath.id != 2:
            return

        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)


       # Ajouter règle C1 ---> LB ---> WS1
        match = parser.OFPMatch(ipv4_src=C1_IP, ipv4_dst=PUB_WS_IP)  # C1 vers WS1 (IP)
        actions = [parser.OFPActionOutput(2)]  # Port vers WS1
        self.add_flow(datapath, 1, match, actions)
        
        # Ajouter règle * <--- LB --- WS1 (retour depuis WS1 vers C1)
        match = parser.OFPMatch(ipv4_src=PUB_WS_IP, ipv4_dst=C1_IP)  # WS1 vers C1 (IP)
        actions = [parser.OFPActionOutput(1)]  # Port vers C1
        self.add_flow(datapath, 1, match, actions)
        
        # Ajouter règle C2 ---> LB ---> WS2
        match = parser.OFPMatch(ipv4_src=C2_IP, ipv4_dst=PUB_WS_IP)  # C2 vers WS2 (IP)
        actions = [parser.OFPActionOutput(3)]  # Port vers WS2
        self.add_flow(datapath, 1, match, actions)
        
        # Ajouter règle * <--- LB --- WS2 (retour depuis WS2 vers C2)
        match = parser.OFPMatch(ipv4_src=PUB_WS_IP, ipv4_dst=C2_IP)  # WS2 vers C2 (IP)
        actions = [parser.OFPActionOutput(1)]  # Port vers C2
        self.add_flow(datapath, 1, match, actions)



    # Add entry (instruction apply actions) in flow table 0  
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

