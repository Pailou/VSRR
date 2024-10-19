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

       # Add rule C1 --- LB ---> WS1
        match_c1_to_ws1 = parser.OFPMatch(in_port=1, eth_type=0x0800,
                                  ipv4_dst=PUB_WS_IP, ipv4_src=C1_IP)
        actions_c1_to_ws1 = [parser.OFPActionSetField(eth_dst=WS1_MAC),
                     parser.OFPActionSetField(ipv4_dst=WS1_IP),
                     parser.OFPActionOutput(2)]
        self.add_flow(datapath, 1, match_c1_to_ws1, actions_c1_to_ws1)
        

        # Add rule C2 --- LB ---> WS2
        match_c2_to_ws2 = parser.OFPMatch(in_port=1, eth_type=0x0800,
                                          ipv4_dst=PUB_WS_IP, ipv4_src=C2_IP)
        actions_c2_to_ws2 = [parser.OFPActionSetField(eth_dst=WS2_MAC),
                             parser.OFPActionSetField(ipv4_dst=WS2_IP),
                             parser.OFPActionOutput(3)]
        self.add_flow(datapath, 1, match_c2_to_ws2, actions_c2_to_ws2)

        # Add rule for WS1 ---> LB ---> C1 (return traffic)
        match_ws1_to_c1 = parser.OFPMatch(in_port=2, eth_type=0x0800,
                                          ipv4_src=WS1_IP, ipv4_dst=C1_IP)
        actions_ws1_to_c1 = [parser.OFPActionSetField(eth_src=PUB_WS_MAC),
                             parser.OFPActionSetField(ipv4_src=PUB_WS_IP),
                             parser.OFPActionOutput(1)]
        self.add_flow(datapath, 1, match_ws1_to_c1, actions_ws1_to_c1)

        # Add rule for WS2 ---> LB ---> C2 (return traffic)
        match_ws2_to_c2 = parser.OFPMatch(in_port=3, eth_type=0x0800,
                                          ipv4_src=WS2_IP, ipv4_dst=C2_IP)
        actions_ws2_to_c2 = [parser.OFPActionSetField(eth_src=PUB_WS_MAC),
                             parser.OFPActionSetField(ipv4_src=PUB_WS_IP),
                             parser.OFPActionOutput(1)]
        self.add_flow(datapath, 1, match_ws2_to_c2, actions_ws2_to_c2)



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

