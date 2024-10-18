# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# EDIT E. Lavinal
#   - code based on Ryu's Simple Switch 13
#   - new version with:
#       - no state on the controller (i.e. no mac_to_port dict)
#       - 2 OF tables (one to learn, one to forward)

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types


class SimpleSwitch2Tables(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch2Tables, self).__init__(*args, **kwargs)

    # Switch features handler
    # ========================
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry in table 0 (learn)
        # --------------------------------------------------
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions),
                parser.OFPInstructionGotoTable(table_id=1)]
        self.add_flow(datapath, 0, match, inst, table=0, idle_timeout=0)
        
        # install table-miss flow entry in table 1 (forward)
        # --------------------------------------------------
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        self.add_flow(datapath, 0, match, inst, table=1, idle_timeout=0)

    # Packet in handler
    # ==================
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if (eth.ethertype == ether_types.ETH_TYPE_LLDP or 
            eth.ethertype == ether_types.ETH_TYPE_IPV6):
            # ignore LLDP and IPv6 packets
            return
        
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.logger.info("packet in on sw %s from %s to %s (in port %s)",
                         dpid, src, dst, in_port)
        
        # Modify flow tables on switch
        # ==============================
        
        # Install forwarding entry in table 1 (avoid FLOOD next time)
        match = parser.OFPMatch(eth_dst=dst)
        actions = [parser.OFPActionOutput(in_port)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        self.add_flow(datapath, 1, match, inst, table=1)
        
        # Install "stop learning" entry in table 0 (avoid PACKET IN next time)
        match = parser.OFPMatch(in_port=in_port, eth_src=src)
        instructions = [parser.OFPInstructionGotoTable(table_id=1)]
        self.add_flow(datapath, 1, match, instructions, table=0)

       



    # Utility function for the OF Modify Flow entry message
    # ======================================================
    def add_flow(self, datapath, priority, match, instructions, table=0, idle_timeout=60):

        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(datapath=datapath, table_id=table, priority=priority,
                                match=match, instructions=instructions,
                                idle_timeout=idle_timeout)
        datapath.send_msg(mod)
