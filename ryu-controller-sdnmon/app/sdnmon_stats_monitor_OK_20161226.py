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

"""
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

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

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
"""

#thien
import struct
from struct import calcsize
from operator import attrgetter

from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.ofproto import ofproto_v1_3_parser
from datetime import datetime
from ryu.ofproto import ofproto_v1_3 as ofproto
#from ryu.ofproto import ofproto_v1_4_parser

class SimpleMonitor(simple_switch_13.SimpleSwitch13):
    
    def __init__(self, *args, **kwargs):
        super(SimpleMonitor, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
    
    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]
    
    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
                
                #Thien - test setSamplingRatio
                #ratio=0x05 
                #self._set_sampling_ratio(dp, ratio)
            
            hub.sleep(10)
    
    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        #ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        #req = parser.OFPFlowStatsRequest(datapath)
        #datapath.send_msg(req)
        
        #req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        #datapath.send_msg(req)

            #req = datapath.ofproto_v1_3_parser.OFPExperimenter(datapath)
#         exp=10
#         exp_type=2
#         data=bytearray([0xFF])
#         #req = parser.OFPExperimenter(datapath, experimenter=0x01, exp_type=0x02, data="1")
#         req = parser.OFPExperimenter(datapath, experimenter=exp, exp_type=exp_type, data=data)
#         datapath.send_msg(req)
#         self.logger.info('--------------')
#         self.logger.info(datetime.now())
#         self.logger.info('                          Sent EXPERIMENTER Request (setSamplingRatio) to Switch.')
        #self.logger.info('                          Sent EXPERIMENTER Multipart Request to Switch.')
        
        #datetime.time(datetime.now())
        #time(15, 8, 24, 78915)
        data=bytearray([])
        req = parser.OFPExperimenterStatsRequest(datapath, flags =0, experimenter=10, exp_type=1, data=data, type_=None)
        datapath.send_msg(req)
        self.logger.info('--------------')
        self.logger.info(datetime.now())
        self.logger.info('                          Sent EXPERIMENTER Multipart Request to Switch.')

    
    def _set_sampling_ratio(self, datapath, ratio):
        self.logger.debug('send set_sampling_ratio request: %016x', datapath.id)
        #ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        exp=10
        exp_type=1
        #hex_ratio=hex(ratio)
        data=bytearray([ratio])
        #req = parser.OFPExperimenter(datapath, experimenter=0x01, exp_type=0x02, data="1")
        req = parser.OFPExperimenter(datapath, experimenter=exp, exp_type=exp_type, data=data)
        datapath.send_msg(req)
        self.logger.info('--------------')
        self.logger.info(datetime.now())
        self.logger.info('                          Sent setSamplingRatio instruction to Switch.')        
    
    
    
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        
        self.logger.info('datapath         '
                         'in-port  eth-dst           '
                         'out-port packets  bytes')
        self.logger.info('---------------- '
                         '-------- ----------------- '
                         '-------- -------- --------')
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            self.logger.info('%016x %8x %17s %8x %8d %8d',
                                                ev.msg.datapath.id,
                                                stat.match['in_port'], stat.match['eth_dst'],
                                                stat.instructions[0].actions[0].port,
                                                stat.packet_count, stat.byte_count)
    
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        
        self.logger.info('datapath         port     '
                         'rx-pkts  rx-bytes rx-error '
                         'tx-pkts  tx-bytes tx-error')
        self.logger.info('---------------- -------- '
                         '-------- -------- -------- '
                         '-------- -------- --------')
        for stat in sorted(body, key=attrgetter('port_no')):
            self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
                             ev.msg.datapath.id, stat.port_no,
                             stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                             stat.tx_packets, stat.tx_bytes, stat.tx_errors)

#THIEN: 2016-05-04
    @set_ev_cls(ofp_event.EventOFPExperimenter, MAIN_DISPATCHER)
    def _experimenter_handler(self, ev):
        self.logger.info('Received EXPERIMENTER message from Switch')
        
        #test printing out m_entry_stats_list received in Experimenter Reply from switch 
        #body = ev.msg.body
        #self.logger.info('datapath         ''packets  bytes')
            #for stat in sorted(body):
            #self.logger.info('%016x %8d %8d',
    #                 ev.msg.datapath.id, stat.packet_count, stat.byte_count)

    @set_ev_cls(ofp_event.EventOFPExperimenterStatsReply, MAIN_DISPATCHER)
    def _experimenter_mp_handler(self, ev):
        body = ev.msg.body
        
        M_ENTRY_BUCKET_COUNTER_PACK_STR = '!Q' #'!IIHHB3xQQ' #'!IIHHBQQII' # #'!QQ' #'!HHQQ'  # '!HHBQQ' #'!QQ'
        M_ENTRY_BUCKET_COUNTER_SIZE = 8  #32 #29 #37 #29 #16 #32 # 16 bytes: packet_count+byte_count, 4 bytes: srcPort+dstPort, 1 byte: proto, 8bytes: srcIp+dstIp (uint32_t), 
                                        #And: experimenter (4bytes), exp_type (4bytes) => 29 + 4 + 4 = 37 bytes !! 
        assert calcsize(M_ENTRY_BUCKET_COUNTER_PACK_STR) == M_ENTRY_BUCKET_COUNTER_SIZE
        
        self.logger.info(datetime.now())
        self.logger.info('Received EXPERIMENTER Multipart Reply from Switch.')          
        print('msg.body: ', body)
        #test printing out m_entry_stats_list received in Experimenter Reply from switch
        m_entry_list = []
        offset = 0 #0

        body_stats = []       
        for stat in sorted(body):
            body_stats.append(stat)
        self.logger.info('Number of stats in msg.body: %u', len(body_stats))
 
        #test
        data = body_stats[2]
        #print('Data: ', data)
        data_len = len(data)
        print('data_len:', data_len)
        
        self.logger.info('datapath_id      src_ip    dst_ip    src_port    dst_port    proto    packets    bytes')       
        while(offset < data_len):
            m_entry = struct.unpack_from(
                M_ENTRY_BUCKET_COUNTER_PACK_STR, data, offset)
            print('m_entry: ', m_entry[0] - 2251799813685248) #& 0xFFF7FFFFFFFFFFFF)
            m_entry_list.append(m_entry)
            offset += M_ENTRY_BUCKET_COUNTER_SIZE
            
        self.logger.info('#entry in m_entry_list: %u', len(m_entry_list))
    
        
#         for stat in sorted(body):
#             m_entry = []
#             #self.logger.info('%016x %i %i', ev.msg.datapath.id, stat.experimenter, stat.exp_type) #stat.packet_count, stat.byte_count)
#             #m_entry.append(ev.msg.datapath.id)
#             print('Stat: ', stat)
            

            
#             data=stat.data
#             #print('Stat data: ', data)
#             
#             m_entry_stats_length = len(data)
#             #self.logger.info('stat.data length: %u', m_entry_stats_length)
#             #self.logger.info('Stat da    printf(" + srcIp_encode = %d", srcIp_encode);
#             
#             while (offset < m_entry_stats_length): # (m_entry_stats_length - offset > 0):
#                 #unpack a m_entry_stats from buf
#                 #m_entry_stats = struct.unpack_from(ofproto.OFP_BUCKET_COUNTER_PACK_STR, data, 0)
#                 m_entry_stats = struct.unpack_from(
#                     M_ENTRY_BUCKET_COUNTER_PACK_STR, data, offset)
#                     
#                 #m_entry_stats = list(m_entry_stats)
#                 
#                 #m_entry_stats = [x.rstrip(b'\0') for x in m_entry_stats]
#                 #stats = cls(*m_entry_stats)
#                 #self.logger.info('number of items in m_entry_stats: %u', len(m_entry_stats))
#                 #ofproto.OFP_FLOW_STATS_0_SIZE
#                 #m_entry.append(m_entry_stats)
#                 m_entry = m_entry_stats
#                 m_entry_list.append(m_entry)
#                 #m_entry_stats_list.append(m_entry_stats)
#                 
#                 self.logger.info('%04x    %8u', ev.msg.datapath.id,
#                                  m_entry_stats[0] ) #, m_entry_stats[0], m_entry_stats[2], m_entry_stats[3], 
#                                 #m_entry_stats[4], m_entry_stats[6], m_entry_stats[1])
#                 
#                 offset += 8 #32 #29 #37 #29 #16 #32
#                 #m_entry_stats_length -= 32 #29 #37 #16 #32;
            
            
        #for m_entry in m_entry_list:
        #    self.logger.info('%04x    %u    %u    %u    %u    %u    %u    %u', m_entry[0],  
        #                     m_entry[1][0], m_entry[1][1], m_entry[1][2], m_entry[1][3], 
        #                     m_entry[1][4], m_entry[1][5], m_entry[1][6]) #, m_entry[1][7], m_entry[1][8])
                            #m_entry[1][1], m_entry[1][0]) #m_entry[1][2], m_entry[1][1], m_entry[1][3], m_entry[1][0]) 
        #self.logger.info('number of entry in m_entry_list: %u', len(m_entry_list))

        #self.logger.info('%8d', data)

#     @set_ev_cls(ofp_event.EventOFPSDNMonStatsReply, MAIN_DISPATCHER)
#     def _experimenter_mp_handler(self, ev):
#         self.logger.info(datetime.now())
#         self.logger.info('                          Received SDN-Mon (Experimenter) Multipart Reply from Switch.')
#          
#         #test printing out m_entry_stats_list received in Experimenter Reply from switch
#         body = ev.msg.body
#         self.logger.info('datapath         ' 'packets  bytes')
#         for stat in sorted(body):
#             self.logger.info('%016x', ev.msg.datapath.id) #, stat.packet_count, stat.byte_count)
