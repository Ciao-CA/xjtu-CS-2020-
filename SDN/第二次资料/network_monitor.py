# -*- coding: utf-8 -*-
from __future__ import division

from collections import defaultdict
from operator import attrgetter
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet
from collections import defaultdict
import time

SLEEP_PERIOD = 2
ISOTIMEFORMAT='%Y-%m-%d %X'


class Network_Monitor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _NAME = 'Network_Monitor'

    def __init__(self, *args, **kwargs):
        super(Network_Monitor, self).__init__(*args, **kwargs)

        self.datapaths = {}
        self.port_stats = {}
        self.port_speed = {}
        self.flow_stats = {}
        self.flow_speed = {}
        self.get_flow_speed_dict = {}
        self.stats = {}
        self.DpidPort_to_ip = {}

        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            self.stats['port'] = defaultdict(lambda: None)
            self.stats['flow'] = defaultdict(lambda: None)
            for datapath in self.datapaths.values():
                self._request_stats(datapath)
            hub.sleep(SLEEP_PERIOD)
            # self.logger.info("port speed : %s", self.get_port_speed(1, 2))


    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # The controller uses this message to query information about ports statistics.
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

        # The controller uses this message to query individual flow statistics.
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    def _save_stats(self, dist, key, value, length):
        if key not in dist:
            dist[key] = []
        dist[key].append(value)

        if len(dist[key]) > length:
            dist[key].pop(0)

    def _get_speed(self, now, pre, period):
        if period:
            return (now - pre) / period
        else:
            return 0

    def _get_time(self, sec, nsec):
        return sec + nsec / (10 ** 9)

    def _get_period(self, n_sec, n_nsec, p_sec, p_nsec):
        return self._get_time(n_sec, n_nsec) - self._get_time(p_sec, p_nsec)

    def get_port_speed(self, sw_src=None, src_port=None):
        if sw_src is None or src_port is None:
            return self.port_speed
        return self.port_speed.get((sw_src, src_port), (None, None))



    # def get_port_speed(self, dpid=None, port=None):
    #     if dpid is None or port is None:
    #         return self.port_speed
    #     return self.port_speed.get((dpid, port), None)
    #
    # def get_flow_speed(self, dpid=None):
    #     if dpid is None:
    #         return self.flow_speed
    #     else:
    #         return self.flow_speed[dpid]
    # EventOFPFlowStatsReply: switch will reply all of its flows (on flow table) to controller
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        self.stats['flow'][dpid] = body
        self.flow_stats.setdefault(dpid, {})
        self.flow_speed.setdefault(dpid, {})
        flow_list = {}
        for flow in body:
            if (flow.priority != 0) and (flow.priority != 65535):
                key = (flow.match.get('in_port', 0), flow.match.get('ipv4_src', 'all'), flow.match.get('ipv4_dst', 'all'))
                value = (flow.packet_count, flow.byte_count, flow.duration_sec, flow.duration_nsec)
                flow_list[key] = value
                # 从每一条流表项中取出outport消息
                out_port = flow.instructions[0].actions[-1].port
                key1 = (dpid, out_port)
                value1 = (flow.match.get('ipv4_src', 'all'), flow.match.get('ipv4_dst', 'all'))
                self.DpidPort_to_ip[key1] = value1
                # self.logger.info("tmp : %s", str(tmp))
                # self.logger.info("flow : %s", str(flow))
                # self.logger.info("DpidPort_to_ip : %s", str(self.DpidPort_to_ip))
        # self.logger.info("flow_list : %s", str(flow_list))
        # have delete the flow_list in switch, so the key in flow_stats is not equal flow_list
        for key in self.flow_stats[dpid]:
            if key not in flow_list:
                # the flow has been delete
                #self.logger.info("key : %s", str(key))
                value = (0, 0, 0, 0)
                self._save_stats(self.flow_stats[dpid], key, value, 20)
                self._save_stats(self.flow_speed[dpid], key, 0, 20)

        for key in flow_list:
            self._save_stats(self.flow_stats[dpid], key, flow_list[key], 20)
            # Get flow's speed.
            pre = 0
            period = SLEEP_PERIOD

            tmp = self.flow_stats[dpid][key]
            if len(tmp) > 1:
                pre = tmp[-2][1]
                period = self._get_period(tmp[-1][2], tmp[-1][3], tmp[-2][2], tmp[-2][3])
            speed = self._get_speed(self.flow_stats[dpid][key][-1][1], pre, period) * 8
            # self.logger.info("flow_speed: %s", speed)
            self.save_flow_speed(dpid, key[1], key[2], speed)
            self._save_stats(self.flow_speed[dpid], key, speed, 20)
            # self.logger.info("monitor get_flow_speed_dict address: %s", id(self.get_flow_speed_dict))

        for key in self.flow_stats[dpid]:
            if key not in flow_list:
                temp_key = (dpid, key[1], key[2])
                if self.get_flow_speed_dict.get(temp_key) is not None:
                    del self.get_flow_speed_dict[temp_key]
            # self.logger.info("get_flow_speed_dict : %s", self.get_flow_speed_dict)

    def save_flow_speed(self, dpid, src_ip, dst_ip, speed):
        # judge the key???
        key = (dpid, src_ip, dst_ip)
        value = speed
        self.get_flow_speed_dict[key] = value

    # def get_flow_speed(self, dpid, src_ip, dst_ip):
    #     if dpid and src_ip and dst_ip:
    #         key = (dpid, src_ip, dst_ip)
    #         #self.logger.info("flow_speed_dict: %s", self.get_flow_speed_dict.keys())
    #         return self.get_flow_speed_dict.keys()
    #
    #     else:
    #         return

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        self.stats['port'][ev.msg.datapath.id] = body
        for stat in sorted(body, key=attrgetter('port_no')):
            if stat.port_no != ofproto_v1_3.OFPP_LOCAL:
                key = (ev.msg.datapath.id, stat.port_no)
                value = (stat.tx_bytes, stat.rx_bytes, stat.rx_errors, stat.duration_sec, stat.duration_nsec)

                self._save_stats(self.port_stats, key, value, 5)

                # Get port speed.
                pre = 0
                period = SLEEP_PERIOD
                tmp = self.port_stats[key]
                if len(tmp) > 1:
                    pre = tmp[-2][0]
                    period = self._get_period(tmp[-1][3], tmp[-1][4], tmp[-2][3], tmp[-2][4])

                speed = self._get_speed(self.port_stats[key][-1][0], pre, period)

                # Downlink bandwidth
                # self.port_speed = {(dpid,port):speed}
                # speed bps
                self.port_speed[key] = (speed * 8, time.strftime( ISOTIMEFORMAT, time.localtime()))

       # self.logger.info("port speed : %s", str(self.port_speed))
