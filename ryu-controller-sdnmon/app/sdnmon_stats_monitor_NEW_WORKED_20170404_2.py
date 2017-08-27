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
import time
import csv
import collections
import struct
from struct import calcsize
from operator import attrgetter

from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.ofproto import ofproto_v1_3_parser
from datetime import datetime, timedelta
from ryu.ofproto import ofproto_v1_3 as ofproto
#from ryu.ofproto import ofproto_v1_4_parser

class SDNMONMonitor(simple_switch_13.SimpleSwitch13):
    global_m_tables = None #GMTs: Global Monitoring Tables
    load_status_table = None 
    remove_awaiting_lists = None
    buffering_table = None
    
    buffering_counters = None
    global number_of_flows
    global number_of_m_entries  
    sampling_ratios = None
    
    #these are counting variables only for experiment 
    counting_time_experiment = 10
    system_elapsed_time = 0 #in miliseconds (ms)
    algorithm_elapsed_time = 0
    multipart_reply_message_count = 0 
    #####

    def __init__(self, *args, **kwargs):      
        super(SDNMONMonitor, self).__init__(*args, **kwargs)
        self.datapaths = {}
        
        #init a List (dict) that will hold Global monitoring tables
        self.global_m_tables = collections.defaultdict(dict)
        self.remove_awaiting_lists = collections.defaultdict(dict)
        self.buffering_table = collections.defaultdict(dict)
        self.number_of_flows = 0
        self.number_of_m_entries = 0
        #init global_m_table as a global variable
        #self.global_m_table = collections.defaultdict(dict)
        self.load_status_table = collections.defaultdict(dict)
  
        
        self.query_time_interval = 10 
        #current time when a query is sent to switches (in seconds, < 1 day)
        self.query_time = 0
         
        self.sampling_ratios = collections.defaultdict(dict)
        self.buffering_counters = collections.defaultdict(dict)
        
        
        self.monitor_thread = hub.spawn(self._monitor)
        
        #Thread for putting data in GMTs, clean Buffering Table, remove-lists 
        #then send instructions to switches to remove m-entries in remove-lists 
        self.sdnmon_balancing_thread = hub.spawn(self._sdnmon_balancing_cleaner) 
    
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
    
    def _sdnmon_balancing_cleaner(self):
        while True: 
            #check if (current time - query_time) < (query_time_interval/2)
            t = datetime.now()
            current_time = t.second + t.minute*60 + t.hour*3600
             
            #self.logger.info('sdnmon_balancing_cleaner - current_time: %d', current_time)
            if((current_time - self.query_time) == (self.query_time_interval - 2)):
                #self.logger.info('Balancing_cleaner-current_time: %d', current_time)
                algorithm_starting_time = time.time()*1000 #self._get_current_time_milliseconds()
                #self.logger.info('algorithm starting time: %.2f', algorithm_starting_time)
                self.logger.info('')
                self.logger.info('#----------------------------------------------#')
                #self.logger.info("Buffering Table (#entry: %d)", len(self.buffering_table))
                #for k in self.buffering_table.keys():
                #        print('Entry_hash:', k, ' Entry:', self.buffering_table[k])
                
                #self.logger.info('Putting m-entries from Buffering Table to GMTs')
                #put m_entries in Buffering Table into Global Monitoring Table (GMT) of switch corresponding to each entry 
                for entry_hash in self.buffering_table.keys():
                    self.global_m_tables[self.buffering_table[entry_hash]["sw_id"]][entry_hash] = self.buffering_table.get(entry_hash)
       
#                 self.logger.info('#################################')
                self.logger.info('#m_entries in Buffering table: %d)', len(self.buffering_table))
                self.logger.info('Global Monitoring Tables: ')
                for t in self.global_m_tables.keys():
                    switch_table = self.global_m_tables[t]
                    print('GMT-Switch: %d', t, '  #entry: %d', len(switch_table))
#                     for k in switch_table.keys():
#                         print('Entry_hash:', k, ' Entry:', switch_table[k])
                self.logger.info('#----------------------------------------------#')
                self.logger.info('')
                
                self.buffering_table.clear()
                for k in self.buffering_counters.keys():
                    self.buffering_counters[k] = 0
             
                #for experiment 
                if(self.multipart_reply_message_count == len(self.datapaths)):
                    algorithm_processing_time = time.time()*1000 - algorithm_starting_time
                    self.system_elapsed_time += algorithm_processing_time
                    self.logger.info('FINAL SYSTEM ELAPSED TIME of a querying time: %.2f', self.system_elapsed_time)
                    self.system_elapsed_time = 0
                    self.multipart_reply_message_count = 0
                    
                    self.algorithm_elapsed_time += algorithm_processing_time
                    self.logger.info('ALGORITHM ELAPSED TIME of a querying time: %.2f', self.algorithm_elapsed_time)
                    self.logger.info('----------')
                    self.logger.info('')
                    self.algorithm_elapsed_time = 0 
             
                #Write to csv file for experiments 
                total_entries = 0
                new_line = str(self.counting_time_experiment)
                for t in self.global_m_tables.keys():
                    number_entries = len(self.global_m_tables[t])
                    new_line += ' ' + str(number_entries)
                    total_entries += number_entries
                if(total_entries != 0):
                    new_line += ' ' + str(total_entries)
                    for t in self.global_m_tables.keys():
                        number_entries = len(self.global_m_tables[t])
                        new_line += ' ' + str((number_entries * 100.00)/total_entries) 
                    f = open('/home/thien/ryu-controller-experiment-data/test.dat', 'a')  
                    f.write(new_line)    
                    f.write('\n')   
                    f.close()
                    self.counting_time_experiment += 10
                            
            hub.sleep(1)
    
    def _monitor(self):
        count=1
        while True: 
            now = datetime.now()
            self.query_time = now.second + now.minute*60 + now.hour*3600 #timedelta.seconds, hour:minute:second
            #self.logger.info(now)
            #self.logger.info('Query Time: %d', self.query_time) 
            self.system_elapsed_time = time.time()*1000 #self._get_current_time_milliseconds() #round(time.time() * 1000) #current time in miliseconds
            #self.logger.info('monitor starting time (in miliseconds): %.2f', self.system_elapsed_time)
            
            for dp in self.datapaths.values():
                self._request_stats(dp)
                
                
                #Thien - test setSamplingRatio
                #if ((count % 4) == 0):
                ratio= 50 #0x05 
                #self._set_sampling_ratio(dp, ratio)
                query_time_interval=1200 #60s
                #self._set_query_time_interval(dp, query_time_interval)
                overflow_threshold=1000 #chua set duoc value >256 !??
                #self._set_overflow_notification_threshold(dp, overflow_threshold)
                #if(count % 4 == 3):
                #    self._reset_monitoring_table(dp)
                
                #m_entry=[1, 2, 3, 4, 200]
                m_entry1=[[192, 168, 1, 101], [192, 168, 1, 150], 260, 100, 6]
                m_entry2=[[192, 168, 1, 150], [192, 168, 1, 101], 3456, 1234, 6]
                #if(count % 3 == 1):
                #    self._insert_monitoring_entry(dp, m_entry1)
                #if(count % 3 == 0):
                #    self._remove_monitoring_entry(dp, m_entry1)
                
#                 if(count % 4 == 3):
#                     self.logger.info('--------------')
#                     self.logger.info(datetime.now())
#                     #self._export_monitoring_data_to_csv('/home/thien/ryu-controller/monitoring_data_csv/monitoring_data.csv')
#                     self._import_monitoring_data_from_csv('/home/thien/ryu-controller/monitoring_data_csv/import_data.csv')
#                     self.logger.info(datetime.now())
#                     self.logger.info('--------------')
                
            hub.sleep(self.query_time_interval) #hub.sleep(10)
            count+=1
            
    
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
        #self.logger.info('')
        #self.logger.info('#--------------------------------------------------------------------------------------#')
        #self.logger.info(datetime.now())
        #self.logger.info('Sent SDNMON_MULTIPART_REQUEST to Switch: %04x', datapath.id)

    
    def _get_current_time_milliseconds(self, ):
        time_milliseconds = lambda: int(round(time.time() * 1000))
        return time_milliseconds
    
    def _set_sampling_ratio(self, datapath, ratio):
        self.logger.debug('Sent set_sampling_ratio instruction to switch: %04x, ratio=%4d', datapath.id, ratio)
        #ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        exp=10
        exp_type=2
        hex_ratio=hex(ratio)
        data=bytearray([ratio]) #data=bytearray([ratio])
        #req = parser.OFPExperimenter(datapath, experimenter=0x01, exp_type=0x02, data="1")
        req = parser.OFPExperimenter(datapath, experimenter=exp, exp_type=exp_type, data=data)
        datapath.send_msg(req)
        self.logger.info('--------------')
        self.logger.info(datetime.now())
        self.logger.info('Sent SetSamplingRatio instruction to Switch %04x, ratio=%4d', datapath.id, ratio)        
    
    #SDN-MON API: set_query_time_interval 
    #input: query_time_interval (seconds): an integer value
    def _set_query_time_interval(self, datapath, query_time_interval):
        self.logger.debug('Sent set_query_time_interval instruction to switch: %04x', datapath.id)
        parser = datapath.ofproto_parser      
        
        exp=10
        exp_type=3
        data=bytearray()
        #query_time_interval: 4 bytes
        data.append((query_time_interval & 0xFF)) 
        data.append(((query_time_interval >> 8) & 0xFF))
        data.append(((query_time_interval >> 16) & 0xFF))
        data.append(((query_time_interval >> 24) & 0xFF))
        
        req = parser.OFPExperimenter(datapath, experimenter=exp, exp_type=exp_type, data=data)
        datapath.send_msg(req)
        self.query_time_interval = query_time_interval
        
        self.logger.info('--------------')
        self.logger.info(datetime.now())
        self.logger.info('Sent SetQueryTimeInterval instruction to Switch %04x, query_time_interval=%4d', datapath.id, query_time_interval)        
    
    #SDN-MON API: set_query_time_interval 
    #input: query_time_interval (seconds): an integer value (4 bytes)
    def _set_overflow_notification_threshold(self, datapath, overflow_threshold):
        self.logger.debug('Sent SET_OVERFLOW_NOTIFICATION_THRESHOLD instruction to switch: %04x', datapath.id)
        parser = datapath.ofproto_parser      
        
        exp=10
        exp_type=4
        data=bytearray()
        #overflow_threshold: 4 bytes
        data.append((overflow_threshold & 0xFF)) 
        data.append(((overflow_threshold >> 8) & 0xFF))
        data.append(((overflow_threshold >> 16) & 0xFF))
        data.append(((overflow_threshold >> 24) & 0xFF))
        
        req = parser.OFPExperimenter(datapath, experimenter=exp, exp_type=exp_type, data=data)
        datapath.send_msg(req)
        self.logger.info('--------------')
        self.logger.info(datetime.now())
        self.logger.info('Sent SET_OVERFLOW_NOTIFICATION_THRESHOLD instruction to Switch %04x, overflow_threshold=%4d', datapath.id, overflow_threshold)        
    
    def _reset_monitoring_table(self, datapath):
        self.logger.debug('Sent RESET_MONITORING_TABLE instruction to switch: %04x', datapath.id)
        #ofproto = datapath.ofproto
        parser = datapath.ofproto_parser      
        exp=10
        exp_type=5
        #hex_ratio=hex(ratio)
        data=bytearray()
        #req = parser.OFPExperimenter(datapath, experimenter=0x01, exp_type=0x02, data="1")
        req = parser.OFPExperimenter(datapath, experimenter=exp, exp_type=exp_type, data=data)
        datapath.send_msg(req)
        self.logger.info('--------------')
        self.logger.info(datetime.now())
        self.logger.info('Sent RESET_MONITORING_TABLE instruction to Switch %04x', datapath.id)        
        
    def _insert_monitoring_entry(self, datapath, m_entry):
        self.logger.debug('Sent INSERT_MONITORING_ENTRY instruction to switch: %04x', datapath.id)
        parser = datapath.ofproto_parser      
        
        exp=10
        exp_type=6
        data=bytearray()
        data.extend(m_entry[0])
        data.extend(m_entry[1])
        data.append((m_entry[2] & 0xFF)) 
        data.append(((m_entry[2] >> 8) & 0xFF))
        data.append((m_entry[3] & 0xFF)) 
        data.append(((m_entry[3] >> 8) & 0xFF))
        data.append(m_entry[4])
        
        req = parser.OFPExperimenter(datapath, experimenter=exp, exp_type=exp_type, data=data)
        
        datapath.send_msg(req)
        self.logger.info('--------------')
        self.logger.info(datetime.now())
        self.logger.info('Sent INSERT_MONITORING_ENTRY instruction to Switch %04x, m_entry=[[%d, %d, %d, %d], [%d, %d, %d, %d], %d, %d, %d]', 
                         datapath.id, m_entry[0][0], m_entry[0][1], m_entry[0][2], m_entry[0][3], 
                         m_entry[1][0], m_entry[1][1], m_entry[1][2], m_entry[1][3], m_entry[2], m_entry[3], m_entry[4])        
        
    def _remove_monitoring_entry(self, datapath, m_entry):
        self.logger.debug('Sent REMOVE_MONITORING_ENTRY instruction to switch: %04x', datapath.id)
        parser = datapath.ofproto_parser      
        
        exp=10
        exp_type=7
        data=bytearray()
        data.extend(m_entry[0])
        data.extend(m_entry[1])
        data.append((m_entry[2] & 0xFF)) 
        data.append(((m_entry[2] >> 8) & 0xFF))
        data.append((m_entry[3] & 0xFF)) 
        data.append(((m_entry[3] >> 8) & 0xFF))
        data.append(m_entry[4])
        
        req = parser.OFPExperimenter(datapath, experimenter=exp, exp_type=exp_type, data=data)
        
        datapath.send_msg(req)
        self.logger.info('--------------')
        self.logger.info(datetime.now())
        self.logger.info('Sent REMOVE_MONITORING_ENTRY instruction to Switch %04x, m_entry=[[%d, %d, %d, %d], [%d, %d, %d, %d], %d, %d, %d]', 
                         datapath.id, m_entry[0][0], m_entry[0][1], m_entry[0][2], m_entry[0][3], 
                         m_entry[1][0], m_entry[1][1], m_entry[1][2], m_entry[1][3], m_entry[2], m_entry[3], m_entry[4])        
 
    def _export_monitoring_data_to_csv(self, path_to_csv_file):
        #with open('/Users/thienphan/Lagopus_coding/test_export_monitoring_data/dict.csv', 'wb') as csv_file:
        with open(path_to_csv_file, 'wb') as csv_file:
            writer = csv.writer(csv_file)
            for key, value in self.global_m_table.items():
                writer.writerow([key, value])
        self.logger.info('EXPORTED monitoring database to CSV file')
                
    def _import_monitoring_data_from_csv(self, path_to_csv_file):
        #with open('/Users/thienphan/Lagopus_coding/test_export_monitoring_data/dict.csv', 'rb') as csv_file:
        with open(path_to_csv_file, 'rb') as csv_file:
            reader = csv.reader(csv_file)
            self.global_m_table = dict(reader)
        self.logger.info('IMPORTED monitoring database from CSV file')       
    
    def _int_to_ipaddress(self, int_addr):
        return ".".join(map(lambda n: str(int_addr>>n & 0xFF), [0,8,16,24]))          
    
    ################            
    
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
        m_entries_count = 0
        switch_capacity = 50000
        
        if ev.msg.flags == 0:
            self.multipart_reply_message_count += 1 #for Experiment of algorithm/system elapsed times
        
        #self.logger.info('Received SDNMON_MULTIPART_REPLY from Switch: %04x', ev.msg.datapath.id)
        
#         for m_entry in sorted(body):
#             m_entries_count += 1
# #             self.logger.info('%02x %8d %8d %8d %8d %8d %16d %16d',
# #                              ev.msg.datapath.id, (m_entry.packet_count - 9007199254740992),
# #                              m_entry.byte_count, m_entry.proto, m_entry.src_port,
# #                              m_entry.dst_port, m_entry.src_ip, m_entry.dst_ip)
#         self.logger.info('#Entry received from Switch %d: %u', ev.msg.datapath.id, m_entries_count)
        
        global_m_table = self.global_m_tables.get(ev.msg.datapath.id)
        if(global_m_table == None):
            global_m_table = collections.defaultdict(dict)
            self.global_m_tables[ev.msg.datapath.id] = global_m_table
        remove_list = self.remove_awaiting_lists.get(ev.msg.datapath.id)
        if(remove_list == None):
            remove_list = collections.defaultdict(dict)
            self.remove_awaiting_lists[ev.msg.datapath.id] = remove_list
        if(self.buffering_counters.get(ev.msg.datapath.id) == None):
            self.buffering_counters[ev.msg.datapath.id] = 0
            
        
        if(self.buffering_counters.get(ev.msg.datapath.id) == None):
            self.load_status_table[ev.msg.datapath.id] = {"Nfe":self.number_of_flows, 
                                                       "Nme":len(self.global_m_tables[ev.msg.datapath.id]), #"Nme":numbers_of_entries[1],  
                                                       "switch_capacity":switch_capacity, 
                                                       "usage":self.number_of_m_entries + len(self.global_m_tables[ev.msg.datapath.id]), #*100.0/switch_capacity), #"usage":((self.numbers_of_entries[0] + self.numbers_of_entries[1])*100.0/switch_capacity),                
                                                       "last_update":(datetime.now())}
        else:
            self.load_status_table[ev.msg.datapath.id] = {"Nfe":self.number_of_flows, 
                                                       "Nme":(len(self.global_m_tables[ev.msg.datapath.id]) + self.buffering_counters[ev.msg.datapath.id]), # + self.buffering_counters[ev.msg.datapath.id]), #"Nme":numbers_of_entries[1],  
                                                       "switch_capacity":switch_capacity, 
                                                       "usage":(self.number_of_m_entries + (len(self.global_m_tables[ev.msg.datapath.id]) + self.buffering_counters[ev.msg.datapath.id])), #*100.0/switch_capacity), #"usage":((self.numbers_of_entries[0] + self.numbers_of_entries[1])*100.0/switch_capacity),                
                                                       "last_update":(datetime.now())}
            
        m_entries_catagorizer_starting_time = time.time()*1000    
        for m_entry in sorted(body):
            m_entries_count += 1
            #test inserting entry to global_m_table
            entry_hash_value = hash((m_entry.src_ip, m_entry.dst_ip, m_entry.src_port, m_entry.dst_port, m_entry.proto))
            #Check if there a duplicate entry in Buffering Table
            entryY = self.buffering_table.get(entry_hash_value)
            if(entryY == None):
                self.buffering_table[entry_hash_value] = {"sw_id":ev.msg.datapath.id, "src_ip":self._int_to_ipaddress(m_entry.src_ip), "dst_ip":self._int_to_ipaddress(m_entry.dst_ip), 
                                                     "src_port":m_entry.src_port, "dst_port":m_entry.dst_port, "proto":m_entry.proto, 
                                                     "packet_count":(m_entry.packet_count - 9007199254740992), "byte_count":m_entry.byte_count}
                self.buffering_counters[ev.msg.datapath.id] += 1
                self.load_status_table[ev.msg.datapath.id]["Nme"] += 1
                #self.logger.info('Nme switch %d: %d', ev.msg.datapath.id, self.load_status_table[ev.msg.datapath.id]["Nme"]) 
                self.load_status_table[ev.msg.datapath.id]["usage"] = (self.number_of_m_entries + (len(self.global_m_tables[ev.msg.datapath.id]) + self.buffering_counters[ev.msg.datapath.id])) #*100.0/switch_capacity
            else:   #dulicate entry existed, assuming that entry is entryY
                switch_id_entryY = entryY["sw_id"]
                if(self.load_status_table[ev.msg.datapath.id]["Nme"] < self.load_status_table[switch_id_entryY]["Nme"]):
                    #Insert the checking entry into Buffering Table
                    self.buffering_table[entry_hash_value] = {"sw_id":ev.msg.datapath.id, "src_ip":self._int_to_ipaddress(m_entry.src_ip), "dst_ip":self._int_to_ipaddress(m_entry.dst_ip), 
                                                     "src_port":m_entry.src_port, "dst_port":m_entry.dst_port, "proto":m_entry.proto, 
                                                     "packet_count":(m_entry.packet_count - 9007199254740992), "byte_count":m_entry.byte_count}
                    #update buffering_counter
                    if(self.buffering_counters.get(switch_id_entryY) == None):
                        self.buffering_counters[switch_id_entryY] = 1
                    else: 
                        self.buffering_counters[switch_id_entryY] += 1
                     
                    self.load_status_table[switch_id_entryY]["Nme"] -= 1
                    self.load_status_table[ev.msg.datapath.id]["Nme"] += 1 
                    #self.logger.info('Nme switch %d: %d', ev.msg.datapath.id, self.load_status_table[ev.msg.datapath.id]["Nme"]) 
                    self.load_status_table[ev.msg.datapath.id]["usage"] = (self.number_of_m_entries + (len(self.global_m_tables[ev.msg.datapath.id]) + self.buffering_counters[ev.msg.datapath.id])) #*100.0/switch_capacity   
                    #Insert entryY into Remove List of its switch (switch_id_entryY)
                    self.remove_awaiting_lists.get(switch_id_entryY)[entry_hash_value] = entryY
                else: 
                    self.remove_awaiting_lists.get(ev.msg.datapath.id)[entry_hash_value] = {"sw_id":ev.msg.datapath.id, "src_ip":self._int_to_ipaddress(m_entry.src_ip), "dst_ip":self._int_to_ipaddress(m_entry.dst_ip), 
                                                     "src_port":m_entry.src_port, "dst_port":m_entry.dst_port, "proto":m_entry.proto, 
                                                     "packet_count":(m_entry.packet_count - 9007199254740992), "byte_count":m_entry.byte_count}
             
        self.logger.info('#Entry received from Switch %d: %u', ev.msg.datapath.id, m_entries_count)
         
        #for experiment, calculate time spent since first Request sent until complete receiving all Replies 
        self.algorithm_elapsed_time += (time.time()*1000 - m_entries_catagorizer_starting_time)
        if(self.multipart_reply_message_count == len(self.datapaths)):
            self.system_elapsed_time = time.time()*1000 - self.system_elapsed_time











        
#     @set_ev_cls(ofp_event.EventOFPExperimenterStatsReply, MAIN_DISPATCHER)
#     def _experimenter_mp_handler(self, ev):
#         body = ev.msg.body
#         
#         M_ENTRY_BUCKET_COUNTER_PACK_STR = '!QQ3xBHHII' #'!Q' #'!IIHHB3xQQ' #'!IIHHBQQII' # #'!QQ' #'!HHQQ'  # '!HHBQQ' #'!QQ'
#         M_ENTRY_BUCKET_COUNTER_SIZE = 32 #24 #20 #16  #8  #32 #29 #37 #29 #16 #32 # 16 bytes: packet_count+byte_count, 4 bytes: srcPort+dstPort, 1 byte: proto, 8bytes: srcIp+dstIp (uint32_t), 
#                                         #And: experimenter (4bytes), exp_type (4bytes) => 29 + 4 + 4 = 37 bytes !! 
#         assert calcsize(M_ENTRY_BUCKET_COUNTER_PACK_STR) == M_ENTRY_BUCKET_COUNTER_SIZE
#         
#         NUMBERS_OF_ENTRIES_BUCKET_COUNTER_PACK_STR = '!II' #for values: number_of_flow_entry (4 bytes), number_of_m_entry (4 bytes)
#         NUMBERS_OF_ENTRIES_BUCKET_COUNTER_SIZE = 8 
#         assert calcsize(NUMBERS_OF_ENTRIES_BUCKET_COUNTER_PACK_STR) == NUMBERS_OF_ENTRIES_BUCKET_COUNTER_SIZE
#         
#         self.multipart_reply_message_count += 1 #for Experiment 
#         self.logger.info(datetime.now())
#         #self.logger.info('Received SDNMON_MULTIPART_REPLY from Switch: %04x', ev.msg.datapath.id)          
#         #print('msg.body: ', body)
#         #test printing out m_entry_stats_list received in Experimenter Reply from switch
#         
#         #set_sampling_ratio
# #         if(self.sampling_ratios.has_key(ev.msg.datapath.id) == False):
# #             self._set_sampling_ratio(ev.msg.datapath, 100)
# #             self.sampling_ratios[ev.msg.datapath.id] = 100 #100% means sampling ratio = 1.0     
#         if(self.buffering_counters.get(ev.msg.datapath.id) == None):
#             self.buffering_counters[ev.msg.datapath.id] = 0
#    
#         m_entry_list = []
#         offset = 0 #0
#         body_stats = []       
#         for stat in sorted(body):
#             body_stats.append(stat)
#         #self.logger.info('Number of stats in msg.body: %u', len(body_stats))
#  
#         #test
#         data = body_stats[2]
#         #print('Data: ', data)
#         data_len = len(data)
#         #print('data_len:', data_len)
#         
#         self.numbers_of_entries = struct.unpack_from(
#                     NUMBERS_OF_ENTRIES_BUCKET_COUNTER_PACK_STR, data, offset)
#         offset += NUMBERS_OF_ENTRIES_BUCKET_COUNTER_SIZE
#         #self.logger.info('#flow_entry:%u', numbers_of_entries[0])
#         #self.logger.info('#m_entry:%u', numbers_of_entries[1])
#         switch_capacity = 50000
#         
#         if(self.buffering_counters.get(ev.msg.datapath.id) == None):
#             self.load_status_table[ev.msg.datapath.id] = {"Nfe":self.numbers_of_entries[0], 
#                                                        "Nme":len(self.global_m_tables[ev.msg.datapath.id]), #"Nme":numbers_of_entries[1],  
#                                                        "switch_capacity":switch_capacity, 
#                                                        "usage":self.numbers_of_entries[0] + len(self.global_m_tables[ev.msg.datapath.id]), #*100.0/switch_capacity), #"usage":((self.numbers_of_entries[0] + self.numbers_of_entries[1])*100.0/switch_capacity),                
#                                                        "last_update":(datetime.now())}
#         else:
#             self.load_status_table[ev.msg.datapath.id] = {"Nfe":self.numbers_of_entries[0], 
#                                                        "Nme":(len(self.global_m_tables[ev.msg.datapath.id]) + self.buffering_counters[ev.msg.datapath.id]), # + self.buffering_counters[ev.msg.datapath.id]), #"Nme":numbers_of_entries[1],  
#                                                        "switch_capacity":switch_capacity, 
#                                                        "usage":(self.numbers_of_entries[0] + (len(self.global_m_tables[ev.msg.datapath.id]) + self.buffering_counters[ev.msg.datapath.id])), #*100.0/switch_capacity), #"usage":((self.numbers_of_entries[0] + self.numbers_of_entries[1])*100.0/switch_capacity),                
#                                                        "last_update":(datetime.now())}
#         
#         #for k in self.load_status_table.keys():
#         #    print('sw_id:', k, ' load_status:', self.load_status_table[k])
#         
#         #self.logger.info('datapath_id          src_ip        dst_ip        src_port    dst_port    proto    #packets    #bytes')       
#         
#         global_m_table = self.global_m_tables.get(ev.msg.datapath.id)
#         if(global_m_table == None):
#             global_m_table = collections.defaultdict(dict)
#             self.global_m_tables[ev.msg.datapath.id] = global_m_table
#         remove_list = self.remove_awaiting_lists.get(ev.msg.datapath.id)
#         if(remove_list == None):
#             remove_list = collections.defaultdict(dict)
#             self.remove_awaiting_lists[ev.msg.datapath.id] = remove_list
#         
#         #test
#         #for k in self.global_m_tables.keys():
#         #    print('Table (switch_id):', k)    
#         ##
#         m_entries_catagorizer_starting_time = time.time()*1000
#         
#         while(offset < data_len):
#             m_entry = struct.unpack_from(
#                 M_ENTRY_BUCKET_COUNTER_PACK_STR, data, offset)
#             #print('original m_entry: ', m_entry)
#             #print('m_entry: ', m_entry[5], m_entry[6], m_entry[3], m_entry[4], m_entry[2], m_entry[0] - 9007199254740992, m_entry[1]) #& 0xFFF7FFFFFFFFFFFF)
# #             self.logger.info('    %04x     %4d.%d.%d.%d    %4d.%d.%d.%d    %8d    %8d    %4d    %8d    %8d',
# #                              ev.msg.datapath.id, 
# #                              (m_entry[5] & 0xFF), ((m_entry[5] >> 8) & 0xFF), ((m_entry[5] >> 16) & 0xFF),((m_entry[5] >> 24) & 0xFF),
# #                              (m_entry[6] & 0xFF), ((m_entry[6] >> 8) & 0xFF), ((m_entry[6] >> 16) & 0xFF),((m_entry[6] >> 24) & 0xFF),
# #                              m_entry[3], m_entry[4], m_entry[2], (m_entry[0] - 9007199254740992), m_entry[1])
# #              
#             m_entry_list.append(m_entry)
#             
#             #test inserting entry to global_m_table
#             entry_hash_value = hash((m_entry[5], m_entry[6], m_entry[3], m_entry[4], m_entry[2]))
#             #Check if there a duplicate entry in Buffering Table
#             entryY = self.buffering_table.get(entry_hash_value)
#             if(entryY == None):
#                 self.buffering_table[entry_hash_value] = {"sw_id":ev.msg.datapath.id, "src_ip":self._int_to_ipaddress(m_entry[5]), "dst_ip":self._int_to_ipaddress(m_entry[6]), 
#                                                      "src_port":m_entry[3], "dst_port":m_entry[4], "proto":m_entry[2], 
#                                                      "packet_count":(m_entry[0] - 9007199254740992), "byte_count":m_entry[1]}
#                 self.buffering_counters[ev.msg.datapath.id] += 1
#                 self.load_status_table[ev.msg.datapath.id]["Nme"] += 1
#                 #self.logger.info('Nme switch %d: %d', ev.msg.datapath.id, self.load_status_table[ev.msg.datapath.id]["Nme"]) 
#                 self.load_status_table[ev.msg.datapath.id]["usage"] = (self.numbers_of_entries[0] + (len(self.global_m_tables[ev.msg.datapath.id]) + self.buffering_counters[ev.msg.datapath.id])) #*100.0/switch_capacity
#             else:   #dulicate entry existed, assuming that entry is entryY
#                 switch_id_entryY = entryY["sw_id"]
#                 if(self.load_status_table[ev.msg.datapath.id]["Nme"] < self.load_status_table[switch_id_entryY]["Nme"]):
#                     #Insert the checking entry into Buffering Table
#                     self.buffering_table[entry_hash_value] = {"sw_id":ev.msg.datapath.id, "src_ip":self._int_to_ipaddress(m_entry[5]), "dst_ip":self._int_to_ipaddress(m_entry[6]), 
#                                                      "src_port":m_entry[3], "dst_port":m_entry[4], "proto":m_entry[2], 
#                                                      "packet_count":(m_entry[0] - 9007199254740992), "byte_count":m_entry[1]}
#                     #update buffering_counter
#                     if(self.buffering_counters.get(switch_id_entryY) == None):
#                         self.buffering_counters[switch_id_entryY] = 1
#                     else: 
#                         self.buffering_counters[switch_id_entryY] += 1
#                     
#                     self.load_status_table[switch_id_entryY]["Nme"] -= 1
#                     self.load_status_table[ev.msg.datapath.id]["Nme"] += 1 
#                     #self.logger.info('Nme switch %d: %d', ev.msg.datapath.id, self.load_status_table[ev.msg.datapath.id]["Nme"]) 
#                     self.load_status_table[ev.msg.datapath.id]["usage"] = (self.numbers_of_entries[0] + (len(self.global_m_tables[ev.msg.datapath.id]) + self.buffering_counters[ev.msg.datapath.id])) #*100.0/switch_capacity   
#                     #Insert entryY into Remove List of its switch (switch_id_entryY)
#                     self.remove_awaiting_lists.get(switch_id_entryY)[entry_hash_value] = entryY
#                 else: 
#                     self.remove_awaiting_lists.get(ev.msg.datapath.id)[entry_hash_value] = {"sw_id":ev.msg.datapath.id, "src_ip":self._int_to_ipaddress(m_entry[5]), "dst_ip":self._int_to_ipaddress(m_entry[6]), 
#                                                      "src_port":m_entry[3], "dst_port":m_entry[4], "proto":m_entry[2], 
#                                                      "packet_count":(m_entry[0] - 9007199254740992), "byte_count":m_entry[1]}
#             
#             offset += M_ENTRY_BUCKET_COUNTER_SIZE
#         #end while (finish checking an arival list of m_entries from the current switch
#         
#         
#         
#         #for experiment, calculate time spent since first Request sent until complete receiving all Replies 
#         self.algorithm_elapsed_time += (time.time()*1000 - m_entries_catagorizer_starting_time)
#         if(self.multipart_reply_message_count == len(self.datapaths)):
#             self.system_elapsed_time = time.time()*1000 - self.system_elapsed_time
#             
#         self.logger.info('#entry received from Switch %d: %u', ev.msg.datapath.id, len(m_entry_list))
#         

        #check if (current time - query_time) < (query_time_interval/2)
#         t = datetime.now()
#         current_time = t.second + t.minute*60 + t.hour*3600
#         self.logger.info('current_time: %d', current_time)
#         if(current_time - self.query_time > self.query_time_interval):
#             self.logger.info('Putting m-entries from Buffering Table to GMTs')
#             #put m_entries in Buffering Table into Global Monitoring Table (GMT) of switch corresponding to each entry 
#             for entry_hash in self.buffering_table.keys():
#                 self.global_m_tables[self.buffering_table[entry_hash]["sw_id"]][entry_hash] = self.buffering_table.get(entry_hash)
#             
#             #global_m_table[entry_hash_value] = {"sw_id":ev.msg.datapath.id, "src_ip":self._int_to_ipaddress(m_entry[5]), "dst_ip":self._int_to_ipaddress(m_entry[6]), 
#             #                                         "src_port":m_entry[3], "dst_port":m_entry[4], "proto":m_entry[2], 
#             #                                         "packet_count":(m_entry[0] - 9007199254740992), "byte_count":m_entry[1]}                
#             
#        
#         #self.logger.info('Global Monitoring Table:')
#         #for k in global_m_table.keys():
#         #    print('Entry_hash:', k, ' Entry:', global_m_table[k])
#             self.logger.info('#################################')
#             self.logger.info('ALL Global Monitoring Tables:')
#             for t in self.global_m_tables.keys():
#                 print('GMT-Switch: ', t)
#                 switch_table = self.global_m_tables[t]
#                 for k in switch_table.keys():
#                     print('Entry_hash:', k, ' Entry:', switch_table[k])
        
        
        
        #m_list = list(self.global_m_table.values())
        #print(m_list)
        
        
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
