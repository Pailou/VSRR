from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4
from ryu.ofproto import ofproto_v1_3


class DynamicLoadBalancer(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DynamicLoadBalancer, self).__init__(*args, **kwargs)
        self.token = 1  # Variable pour le round-robin
        self.flows = {}  # Dictionnaire pour stocker les flux actifs

    def switch_features_handler(self, ev):
    msg = ev.msg
    datapath = msg.datapath
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser

    # Installer un flux par défaut pour le traitement des paquets entrants
    match = parser.OFPMatch()  # Crée un match vide pour tous les paquets
    actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]  # Redirige vers le contrôleur
    
    # Afficher les types des arguments pour le débogage
    print(f"Adding flow: datapath={datapath}, priority=0, match={match}, actions={actions}")

    # Ajouter un flux par défaut
    self.add_flow(datapath, 0, match, actions, idle_timeout=None)

def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=None):
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser

    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

    # Vérifiez que les paramètres sont du bon type
    print(f"Parameters for add_flow: priority={priority}, match={match}, actions={actions}, buffer_id={buffer_id}, idle_timeout={idle_timeout}")

    # Créer le flux avec un identifiant de tampon si fourni
    if buffer_id:
        flow_mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match,
                                      instructions=inst, buffer_id=buffer_id, idle_timeout=idle_timeout)
    else:
        flow_mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match,
                                      instructions=inst, idle_timeout=idle_timeout)

    # Envoyer le message de flux au commutateur
    datapath.send_msg(flow_mod)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        
        if eth_pkt is None:
            return
        
        ip_pkt_list = pkt.get_protocols(ipv4.ipv4)
        
        if not ip_pkt_list:
            return
        
        ip_pkt = ip_pkt_list[0]
        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst

        # On vérifie si une règle existe déjà pour cette adresse IP source
        if src_ip not in self.flows:
            # Pas de règle existante, ajout d'une nouvelle règle
            self._add_flow(datapath, src_ip, in_port)

        # Réinjecter le paquet dans le flux de données
        self._send_packet(datapath, in_port, msg.data)

    def _add_flow(self, datapath, src_ip, in_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Déterminer le port de sortie selon le token
        if self.token == 1:
            out_port = 1  # Port vers WS1
            self.token = 2  # Passer au prochain port
        else:
            out_port = 2  # Port vers WS2
            self.token = 1  # Passer au port précédent

        # Créer la correspondance pour le flux
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        
        # Créer l'action de sortie
        actions = [parser.OFPActionOutput(out_port)]

        # Ajouter la règle avec un idle_timeout de 30 secondes
        self.add_flow(datapath, 1, match, actions, idle_timeout=30)
        
        # Pour la règle de retour (adresse publique), ajout d'une autre règle
        reverse_match = parser.OFPMatch(eth_type=0x0800, ipv4_dst=src_ip)
        reverse_actions = [parser.OFPActionOutput(in_port)]
        self.add_flow(datapath, 1, reverse_match, reverse_actions, idle_timeout=30)

    def _send_packet(self, datapath, out_port, data):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Créer un message PacketOut pour réinjecter le paquet
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                   in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
        datapath.send_msg(out)
