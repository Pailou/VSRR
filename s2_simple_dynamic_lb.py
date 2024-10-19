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
        self.token = 1  # 1 for WS1, 2 for WS2

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        if datapath.id != 2:
            return

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.msg.datapath

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        
        if eth.ethertype == ether_types.ETH_TYPE_IPV4:
            ipv4 = pkt.get_protocol(ipv4.ipv4)
            if ipv4.dst == PUB_WS_IP:
                self.handle_dynamic_lb(datapath, in_port, ipv4.src)

    def handle_dynamic_lb(self, datapath, in_port, src_ip):
        if self.token == 1:
            dst_mac = WS1_MAC
            dst_ip = WS1_IP
            output_port = 2
        else:
            dst_mac = WS2_MAC
            dst_ip = WS2_IP
            output_port = 3

        # Add flow entry for subsequent packets
        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port, eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=PUB_WS_IP
        )
        actions = [
            datapath.ofproto_parser.OFPActionSetField(eth_dst=dst_mac),
            datapath.ofproto_parser.OFPActionSetField(ipv4_dst=dst_ip),
            datapath.ofproto_parser.OFPActionOutput(output_port)
        ]
        self.add_flow(datapath, 1, match, actions)

        # Update the token for the next flow
        self.token = 1 if self.token == 2 else 2

        # Forward the packet to the appropriate server
        self.send_packet_out(datapath, msg.data, output_port)

    def send_packet_out(self, datapath, data, output_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(output_port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                   in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
        datapath.send_msg(out)

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