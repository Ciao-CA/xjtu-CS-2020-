from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller import ofp_event
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib import hub
from ryu.topology.api import get_all_host, get_all_link, get_all_switch

from ryu.lib.packet import arp
from ryu.lib.packet import ether_types
from ryu.lib import mac
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event, switches
import networkx as nx

ETHERNET = ethernet.ethernet.__name__
ETHERNET_MULTICAST = "ff:ff:ff:ff:ff:ff"
ARP = arp.arp.__name__


class NetworkAwareness(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(NetworkAwareness, self).__init__(*args, **kwargs)
        self.mac_table = {}
        self.arp_anti_loop = {}
        self.arp_table = {}
        self.topo_thread = hub.spawn(self._get_topology)
        self.graph = nx.DiGraph()
        self.topology_api_app = self

    def add_flow(self, datapath, priority, match, actions):
        dp = datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp,
                                priority=priority,
                                match=match,
                                instructions=inst)
        dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        # self.logger.info('switch_features_handler called\n')
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, match, actions)
        # handle packet_in message

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        pkt = packet.Packet(msg.data)  # the identity of switch
        dpid = dp.id
        # the port that receive the packet 
        in_port = msg.match['in_port']
        # get ethernet package 
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        dst = eth_pkt.dst
        src = eth_pkt.src
        # ignore lldp packet 
        if eth_pkt.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        if eth_pkt.ethertype == ether_types.ETH_TYPE_IPV6:
            return

            # get the header list
        header_list = dict((p.protocol_name, p) for p in pkt.protocols if type(p) != str)
        # break the arp loop 
        if dst == ETHERNET_MULTICAST and ARP in header_list:
            arp_dst_ip = header_list[ARP].dst_ip
            if (dpid, src, arp_dst_ip) in self.arp_anti_loop:
                if self.arp_anti_loop[(dpid, src, arp_dst_ip)] != in_port:
                    out = parser.OFPPacketOut(
                        datapath=dp,
                        buffer_id=ofp.OFP_NO_BUFFER,
                        in_port=in_port,
                        actions=[], data=None)
                dp.send_msg(out)
                return
        else:
            self.arp_anti_loop[(dpid, src, arp_dst_ip)] = in_port
        # initialize mac_table[dpid] 
        self.mac_table.setdefault(dpid, {})
        # learn the mac_table 
        """ 
        if self.mac_table[dpid].has_key(src): 
        # break the loop 
        if self.mac_table[dpid][src] != in_port: 
        return 
        else:self.mac_table[dpid][src] = in_port 
        self.logger.info('table[%s][%s] = %s', dpid, src, in_port) 
        """
        # get the out_port 
        if self.mac_table[dpid].has_key(dst):
            out_port = self.mac_table[dpid][dst]
        else:
            out_port = ofp.OFPP_FLOOD

        # update the graph 
        if src not in self.graph:
            self.graph.add_node(src)
            self.graph.add_edge(dpid, src, weight=0, port=in_port)
            self.graph.add_edge(src, dpid, weight=0)
        # find the shortest path 
        if src in self.graph and dst in self.graph and dpid in self.graph:
            # find the shortest path
            path = nx.shortest_path(self.graph, src, dst, weight="weight")
            # check error
            if dpid not in path:
                print ("dpid: ", dpid)
                self.logger.info('dpid: %s not in path', dpid)
                print ("path: ", path)
                return
            # reset out port
            nxt = path[path.index(dpid) + 1]
            out_port = self.graph[dpid][nxt]['port']
            self.mac_table[dpid][dst] = out_port
            # print path
            if nxt == dst:
                print ("path: ", path)
                print ("----------------------Topology")
                for u, adj_u in self.graph.adj.items():
                    for v, eattr in adj_u.items():
                        if u < v:
                            self.logger.info('%2s %2s %d', u, v, eattr['weight'])
                print ("----------------------T")
                # print "dpid: ", dpid
                # print "path: ", path
            # self.logger.info('out_port = table[%s][%s] = %s', dpid, nxt, out_port)
            # else:
            # out_port = ofp.OFPP_FLOOD
            # self.logger.info('%s (%s -> %s)', dpid, src, dst)# get the actions
            actions = [parser.OFPActionOutput(out_port)]
            # send out
            out = parser.OFPPacketOut(
                datapath=dp,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=msg.data)
            dp.send_msg(out)
            # get topology

    def _get_topology(self):

        # wait
        self.logger.info('trying to get topology... please wait.')
        hub.sleep(2)
        # get nodes
        switch_list = get_switch(self.topology_api_app, None)
        switches = [switch.dp.id for switch in switch_list]
        self.graph.add_nodes_from(switches)
        # get edges
        link_list = get_link(self.topology_api_app, None)
        for link in link_list:
            self.graph.add_edge(link.src.dpid, link.dst.dpid, weight=1, port=link.src.port_no)
            self.graph.add_edge(link.dst.dpid, link.src.dpid, weight=1, port=link.dst.port_no)
        # print out
        print("----------------------List of nodes")
        print(self.graph.nodes())
        print("----------------------List of edges")
        print(self.graph.edges())
        print("----------------------Topology")
        for u, adj_u in self.graph.adj.items():
            for v, eattr in adj_u.items():
                if u < v:
                    self.logger.info('%2s %2s   %d', u, v, eattr['weight'])
            print("----------------------T")
            #
        while False:
            self.logger.info('trying to get topology... please wait.')
            hub.sleep(2)
            self.logger.info('\n\n')
            hosts = get_all_host(self)
            switches = get_all_switch(self)
            links = get_all_link(self)
            self.logger.info('hosts:')
            for hosts in hosts:
                self.logger.info(hosts.to_dict())
            self.logger.info('switches:')
            for switch in switches:
                self.logger.info(switch.to_dict())
            self.logger.info('links:')
            for link in links:
                self.logger.info(link.to_dict())
            self.logger.info('\n\n')
            # hub.sleep(10)

    # get topology data 
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):

        # get nodes
        switch_list = get_switch(self.topology_api_app, None)
        switches = [switch.dp.id for switch in switch_list]
        self.graph.add_nodes_from(switches)
        # get edges
        link_list = get_link(self.topology_api_app, None)
        for link in link_list:
            self.graph.add_edge(link.src.dpid, link.dst.dpid, weight=1, port=link.src.port_no)
            self.graph.add_edge(link.dst.dpid, link.src.dpid, weight=1, port=link.dst.port_no)
        # links = [(link.src.dpid, link.dst.dpid, {'port': link.src.port_no}) for link in links_list]
        # self.graph.add_edges_from(links)
        # links = [(link.dst.dpid, link.src.dpid, {'port': link.dst.port_no}) for link in links_list]
        # self.graph.add_edges_from(links)
        return
        print("----------------------List of nodes")
        print(self.graph.nodes())
        print("----------------------List of edges")
        print(self.graph.edges())
        print("----------------------Topology")
        for u, adj_u in self.graph.adj.items():
            for v, eattr in adj_u.items():
                if u < v:
                    self.logger.info('%d - %d', u, v)
