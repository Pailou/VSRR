#
# Dynamic Load Balancer with Round Robin for topology topo_LB.py
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
from ryu.lib.packet import ipv4

# Public server IP and MAC
PUB_WS_IP = '10.0.0.10'
PUB_WS_MAC = '00:11:22:33:44:55'

# Web servers WS1 and WS2 IP and MAC
WS1_IP = '10.0.0.11'
WS1_MAC = '00:00:00:00:00:11'
WS2_IP = '10.0.0.22'
WS2_MAC = '00:00:00:00:00:22'


class DynamicLoadBalancer(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DynamicLoadBalancer, self).__init__(*args, **kwargs)
        self.token = 1  # Token pour round robin (1 -> WS1, 2 -> WS2)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Contrôler uniquement S2
        if datapath.id != 2:
            return

        # Installer la règle de "table-miss" pour rediriger le premier paquet vers le contrôleur
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # Ignorer les paquets LLDP
            return

        # Extraire les informations de l'IP
        ip_pkt = pkt.get_protocols(ipv4.ipv4)[0]
        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst

        # Round robin basé sur le token
        if self.token == 1:
            # Relayage vers WS1
            match = parser.OFPMatch(in_port=in_port, eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=PUB_WS_IP)
            actions = [parser.OFPActionSetField(eth_dst=WS1_MAC), parser.OFPActionSetField(ipv4_dst=WS1_IP), parser.OFPActionOutput(2)]
            self.add_flow(datapath, 1, match, actions, msg.buffer_id)

            # Règle pour retour * <--- LB --- WS1
            match_return = parser.OFPMatch(in_port=2, eth_type=0x0800, ipv4_src=WS1_IP, ipv4_dst=src_ip)
            actions_return = [parser.OFPActionSetField(eth_src=PUB_WS_MAC), parser.OFPActionSetField(ipv4_src=PUB_WS_IP), parser.OFPActionOutput(in_port)]
            self.add_flow(datapath, 1, match_return, actions_return)

            self.token = 2  # Mettre à jour le token

        else:
            # Relayage vers WS2
            match = parser.OFPMatch(in_port=in_port, eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=PUB_WS_IP)
            actions = [parser.OFPActionSetField(eth_dst=WS2_MAC), parser.OFPActionSetField(ipv4_dst=WS2_IP), parser.OFPActionOutput(3)]
            self.add_flow(datapath, 1, match, actions, msg.buffer_id)

            # Règle pour retour * <--- LB --- WS2
            match_return = parser.OFPMatch(in_port=3, eth_type=0x0800, ipv4_src=WS2_IP, ipv4_dst=src_ip)
            actions_return = [parser.OFPActionSetField(eth_src=PUB_WS_MAC), parser.OFPActionSetField(ipv4_src=PUB_WS_IP), parser.OFPActionOutput(in_port)]
            self.add_flow(datapath, 1, match_return, actions_return)

            self.token = 1  # Mettre à jour le token

        # Réinjecter le paquet via PacketOut
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        else:
            data = None

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    # Ajouter une règle dans la table de flux avec un idle_timeout
    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=30):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match, 
                                    instructions=inst, idle_timeout=idle_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, 
                                    instructions=inst, idle_timeout=idle_timeout)
        datapath.send_msg(mod)

