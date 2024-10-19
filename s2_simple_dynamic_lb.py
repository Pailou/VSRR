from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, arp
from ryu.ofproto import ofproto_v1_3


class DynamicLoadBalancer(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DynamicLoadBalancer, self).__init__(*args, **kwargs)
        self.token = 1  # Variable pour le round-robin
        self.WS1_IP = '192.168.1.1'  # Adresse IP de WS1
        self.WS2_IP = '192.168.1.2'  # Adresse IP de WS2
        self.PUB_WS_IP = '192.168.1.100'  # Adresse IP publique
        self.WS1_MAC = '00:11:22:33:44:55'  # Adresse MAC de WS1
        self.WS2_MAC = '00:11:22:33:44:66'  # Adresse MAC de WS2
        self.PUB_WS_MAC = '00:11:22:33:44:77'  # Adresse MAC publique

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Installer un flux par défaut pour le traitement des paquets entrants
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFP_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            flow_mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match,
                                          instructions=inst, buffer_id=buffer_id)
        else:
            flow_mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match,
                                          instructions=inst)

        datapath.send_msg(flow_mod)

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
        ip_pkt_list = pkt.get_protocols(ipv4.ipv4)

        # Vérifiez si la liste de paquets IP n'est pas vide
        if not ip_pkt_list:
            # Si la liste est vide, cela signifie que ce n'est pas un paquet IP, alors ignorez-le
            return

        ip_pkt = ip_pkt_list[0]
        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst

        # Round robin basé sur le token
        if self.token == 1:
            # Relayage vers WS1
            match = parser.OFPMatch(in_port=in_port, eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=self.PUB_WS_IP)
            actions = [parser.OFPActionSetField(eth_dst=self.WS1_MAC), parser.OFPActionSetField(ipv4_dst=self.WS1_IP), parser.OFPActionOutput(2)]
            self.add_flow(datapath, 1, match, actions, msg.buffer_id)

            # Règle pour retour * <--- LB --- WS1
            match_return = parser.OFPMatch(in_port=2, eth_type=0x0800, ipv4_src=self.WS1_IP, ipv4_dst=src_ip)
            actions_return = [parser.OFPActionSetField(eth_src=self.PUB_WS_MAC), parser.OFPActionSetField(ipv4_src=self.PUB_WS_IP), parser.OFPActionOutput(in_port)]
            self.add_flow(datapath, 1, match_return, actions_return)

            self.token = 2  # Mettre à jour le token

        else:
            # Relayage vers WS2
            match = parser.OFPMatch(in_port=in_port, eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=self.PUB_WS_IP)
            actions = [parser.OFPActionSetField(eth_dst=self.WS2_MAC), parser.OFPActionSetField(ipv4_dst=self.WS2_IP), parser.OFPActionOutput(3)]
            self.add_flow(datapath, 1, match, actions, msg.buffer_id)

            # Règle pour retour * <--- LB --- WS2
            match_return = parser.OFPMatch(in_port=3, eth_type=0x0800, ipv4_src=self.WS2_IP, ipv4_dst=src_ip)
            actions_return = [parser.OFPActionSetField(eth_src=self.PUB_WS_MAC), parser.OFPActionSetField(ipv4_src=self.PUB_WS_IP), parser.OFPActionOutput(in_port)]
            self.add_flow(datapath, 1, match_return, actions_return)

            self.token = 1  # Mettre à jour le token

        # Réinjecter le paquet via PacketOut
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        else:
            data = None

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
