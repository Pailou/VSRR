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
PUB_WS_IP  = '10.0.0.10'
PUB_WS_MAC = '00:11:22:33:44:55'

# Web servers WS1 and WS2 IP and MAC
WS1_IP  = '10.0.0.11'
WS1_MAC = '00:00:00:00:00:11'
WS2_IP  = '10.0.0.22'
WS2_MAC = '00:00:00:00:00:22'

class DynamicLoadBalancer(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DynamicLoadBalancer, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.token = 1  # Token pour round robin (1 -> WS1, 2 -> WS2)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if datapath.id != 2:
            return

        # Installer une règle de flux par défaut pour envoyer les paquets au contrôleur
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
            return  # Ignorer les paquets LLDP

        src = eth.src
        dst = eth.dst

        # Vérifier si le paquet est destiné au serveur public
        if dst == PUB_WS_MAC:
            # Choisir le serveur suivant en utilisant round-robin
            if self.token == 1:
                actions = [
                    parser.OFPActionSetField(eth_dst=WS1_MAC),
                    parser.OFPActionSetField(ipv4_dst=WS1_IP),
                    parser.OFPActionOutput(2)  # Sortie vers WS1
                ]
                self.token = 2  # Passer au serveur WS2 pour le prochain paquet
            else:
                actions = [
                    parser.OFPActionSetField(eth_dst=WS2_MAC),
                    parser.OFPActionSetField(ipv4_dst=WS2_IP),
                    parser.OFPActionOutput(3)  # Sortie vers WS2
                ]
                self.token = 1  # Passer au serveur WS1 pour le prochain paquet
            
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=PUB_WS_IP)
            self.add_flow(datapath, 1, match, actions)

        # Envoyer le paquet au port d'entrée
        self.send_packet(datapath, in_port, msg.data)
        
    def send_packet(self, datapath, in_port, data):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(in_port)]
        
        # Créer le message PacketOut
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                   in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
        datapath.send_msg(out)

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
