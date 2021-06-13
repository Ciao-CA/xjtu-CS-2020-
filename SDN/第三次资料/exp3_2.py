from ryu.base import app_manager 
from ryu.controller import ofp_event 
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER 
from ryu.controller.handler import set_ev_cls 
from ryu.ofproto import ofproto_v1_3 
from ryu.lib.packet import packet 
from ryu.lib.packet import ethernet 
from ryu.lib.packet import tcp 
from ryu.lib.packet import ether_types 
from ryu.lib.packet import arp 
import networkx as nx 
from ryu.topology.api import get_switch,get_link 
from ryu.topology import event 
from ryu.base.app_manager import lookup_service_brick 
import time 
from ryu.lib import hub 
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER,CONFIG_DISPATCHER 
from ryu.topology.switches import Switches 
from ryu.topology.switches import LLDPPacket 
class ARP_PROXY_13(app_manager.RyuApp): 
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION] 
	def __init__(self, *args, **kwargs): 
		super(ARP_PROXY_13, self).__init__(*args, **kwargs) 
		self.mac_to_port = {} 
		self.network = nx.DiGraph() 
		self.graph = nx.DiGraph() 
		self.paths = {} 
		self.topology_api_app=self 
		self.echo_latency={} 
		self.request_latency={} 
		self.datapaths={} 
		self.sw_module = lookup_service_brick('switches') 
		self.awareness = lookup_service_brick('awareness') 
		self.network_aware = lookup_service_brick('network_aware') 
		
	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER) 
	def switch_features_handler(self, ev):
		datapath = ev.msg.datapath 
		ofproto = datapath.ofproto 
		parser = datapath.ofproto_parser 
		match = parser.OFPMatch() 
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)] 
		self.add_flow(datapath, 0, match, actions) 
	def add_flow(self, datapath, priority, match, actions, buffer_id=None): 
		ofproto = datapath.ofproto 
		parser = datapath.ofproto_parser 
		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)] 
		if buffer_id: 
			mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match, instructions=inst) 
		else:
			mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst) 
		datapath.send_msg(mod) 
	def mac_learning(self, datapath, src, in_port): 
		self.mac_to_port.setdefault((datapath,datapath.id), {}) 
		# learn a mac address to avoid FLOOD next time. 
		if src in self.mac_to_port[(datapath,datapath.id)]: 
			if in_port != self.mac_to_port[(datapath,datapath.id)][src]: 
				return False 
		else:
			self.mac_to_port[(datapath,datapath.id)][src] = in_port 
			return True 
			
	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER) 
	def _packet_in_handler(self, ev): 
		msg = ev.msg 
		datapath = msg.datapath 
		ofproto = datapath.ofproto 
		parser = datapath.ofproto_parser 
		in_port = msg.match['in_port'] 
		pkt = packet.Packet(msg.data) 
		eth = pkt.get_protocols(ethernet.ethernet)[0] 
		dst = eth.dst
		src = eth.src 
		dpid=datapath.id 
		self.mac_learning(datapath, src, in_port) 
		if eth.ethertype == ether_types.ETH_TYPE_LLDP: 
			try: 
				src_dpid, src_port_no = LLDPPacket.lldp_parse(msg.data) 
				dpid = datapath.id 
				if self.sw_module is None: 
					self.sw_module = lookup_service_brick('switches') 
				if src_dpid not in self.paths.keys(): 
					self.paths.setdefault(src_dpid, {}) 
				for port in self.sw_module.ports.keys(): 
					if src_dpid == port.dpid and src_port_no == port.port_no: 
						port_data = self.sw_module.ports[port] 
						delay = port_data.delay 
						self.request_latency[(src_dpid,dpid)] = delay 
						# print('lldp delay between %s and %s is %fms'%(src_dpid,dpid,delay*1000)) 
						self.network[src_dpid][dpid]['weight'] = self.get_delay(src_dpid, dpid) 
						if dpid in self.network: 
							if dpid not in self.paths[src_dpid]: 
								path = nx.shortest_path(self.network,src_dpid,dpid) 
								self.paths[src_dpid][dpid]=path 
				path = nx.shortest_path(self.network,20,25, weight='weight') 
				print(path) 
				total = 0 
				for i in range(len(path)-1): 
					total += self.get_delay(path[i], path[i+1]) 
						# print("total:", total) 
			except Exception as e: 
				print(e) 
				print("error occured") 
			finally: 
				return 
		if dst in self.mac_to_port[(datapath,datapath.id)]: 
			out_port = self.mac_to_port[(datapath,datapath.id)][dst] 
		else:
			if self.mac_learning(datapath, src, in_port) is False: 
				out_port = ofproto.OFPPC_NO_RECV 
			else:
				out_port = ofproto.OFPP_FLOOD 
					
		actions = [parser.OFPActionOutput(out_port)]
		if out_port != ofproto.OFPP_FLOOD: 
			match = parser.OFPMatch(in_port=in_port, eth_dst=dst) 
			if msg.buffer_id != ofproto.OFP_NO_BUFFER: 
				self.add_flow(datapath, 10, match, actions, msg.buffer_id) 
				return 
			else:
				self.add_flow(datapath, 10, match, actions) 
		data = None 
		if msg.buffer_id == ofproto.OFP_NO_BUFFER: 
			data = msg.data 
		out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data) 
		datapath.send_msg(out) 
		
	def _send_echo_request(self): 
		for datapath in self.datapaths.values(): 
			parser = datapath.ofproto_parser 
			data = "%.6f" % time.time() 
			data=data.encode('utf-8') 
			echo_req = parser.OFPEchoRequest(datapath, data=data) 
			datapath.send_msg(echo_req) 
			
	@set_ev_cls(ofp_event.EventOFPEchoReply, MAIN_DISPATCHER) 
	def echo_reply_handler(self, ev): 
		try: 
			latency = time.time() - eval(ev.msg.data) 
			if ev.msg.datapath.id not in self.echo_latency.keys(): 
				self.echo_latency.setdefault(ev.msg.datapath.id,{}) 
			self.echo_latency[ev.msg.datapath.id] = latency 
			# print('echo latency %s is %fms'%(ev.msg.datapath.id, latency*1000)) 
		except: 
			print("echo reply handler error") 
			return 
	
	def get_delay(self, src, dst): 
		try: 
			fwd_delay = self.request_latency[(src,dst)] 
			re_delay = self.request_latency[(dst,src)] 
			src_latency = self.echo_latency[src] 
			dst_latency = self.echo_latency[dst] 
			delay = (fwd_delay + re_delay - src_latency - dst_latency)*(1000/2) 
			print('the delay between %s and %s dealy is %fms'%(src,dst,delay)) 
			return max(delay, 0)
		except: 
			print("get delay error") 
			return float('inf') 
		
	@set_ev_cls(event.EventSwitchEnter,[CONFIG_DISPATCHER,MAIN_DISPATCHER]) 
	def get_topology(self,ev): 
		#store nodes info into the Graph 
		switch_list = get_switch(self.topology_api_app,None) #------------need to get info,by debug 
		switches = [switch.dp.id for switch in switch_list] 
		self.network.add_nodes_from(switches) 
		
		#store links info into the Graph 
		link_list = get_link(self.topology_api_app,None) 
		#port_no, in_port ---------------need to debug, get diffirent from both 
		links = [(link.src.dpid,link.dst.dpid,{'attr_dict':{'port':link.dst.port_no}}) for link in link_list] #add edge, need src,dst,weigtht 
		self.network.add_edges_from(links) 
		links = [(link.dst.dpid,link.src.dpid,{'attr_dict':{'port':link.dst.port_no}}) for link in link_list] 
		self.network.add_edges_from(links) 
		self._send_echo_request() 
		
	@set_ev_cls(ofp_event.EventOFPStateChange,[MAIN_DISPATCHER, DEAD_DISPATCHER]) 
	def _state_change_handler(self, ev): 
		datapath = ev.datapath 
		if ev.state == MAIN_DISPATCHER: 
			if not datapath.id in self.datapaths: 
				self.logger.debug('Register datapath: %016x', datapath.id) 
				self.datapaths[datapath.id] = datapath 
		elif ev.state == DEAD_DISPATCHER: 
			if datapath.id in self.datapaths: 
				self.logger.debug('Unregister datapath: %016x', datapath.id) 
				del self.datapaths[datapath.id]