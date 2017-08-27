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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4

from ryu.ofproto import ether
from ryu.lib.packet import packet
#from ryu.lib.packet import ethernet
#from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import icmp
from ryu.lib.packet import arp
from ryu.lib.packet import vlan
from ryu.lib import mac


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

    #@THIEN - testing
    def packetIsIP( self, message) :
        pkt = packet.Packet(message.data)
    
        ip = pkt.get_protocol(ipv4.ipv4)
        if ip is not None :
            return True
        return False
    
    def packetIsARP( self, message) :
        pkt = packet.Packet(message.data)
    
        a = pkt.get_protocol(arp.arp)
        if a is not None :
            return True
        return False
    
    def packetIsRequestARP( self, message) :
        pkt = packet.Packet(message.data)
    
        a = pkt.get_protocol(arp.arp)
        if a.opcode == arp.ARP_REQUEST :
            return True
        return False
    
    def packetIsReplyARP( self, message) :
        pkt = packet.Packet(message.data)
    
        a = pkt.get_protocol(arp.arp)
        if a.opcode == arp.ARP_REPLY :
            return True
        return False
    
    def packetIsTCP( self, message) :
        pkt = packet.Packet(message.data)
    
        ip = pkt.get_protocol(ipv4.ipv4)
        if ip is not None and ip.proto == 6 :
            return True
        return False
    
    def packetDstIp( self, message, ipaddr) :
        if self.packetIsIP(message):
            pkt = packet.Packet(message.data)
            ip = pkt.get_protocol(ipv4.ipv4)
            if not cmp(ip.dst, ipaddr):
                return True
        return False
    
    def packetSrcIp( self, message, ipaddr) :
        if self.packetIsIP(message):
            pkt = packet.Packet(message.data)
            ip = pkt.get_protocol(ipv4.ipv4)
            if not cmp(ip.src, ipaddr):
                    return True
        return False
    
    def packetDstTCPPort( self, message, tcpport) :
        if self.packetIsTCP(message) :
            pkt = packet.Packet(message.data)
            dsttcp = pkt.get_protocol(tcp.tcp)
            if dsttcp.dst_port == tcpport :
                return True
        return False
    
    def packetSrcTCPPort( self, message, tcpport) :
        if self.packetIsTCP(message) :
            pkt = packet.Packet(message.data)
            srctcp = pkt.get_protocol(tcp.tcp)
            if srctcp.src_port == tcpport :
                    return True
        return False
    
    def packetArpDstIp( self, message, ipaddr) :
        if self.packetIsARP(message):
            pkt = packet.Packet(message.data)
            a = pkt.get_protocol(arp.arp)
            if not cmp(a.dst_ip, ipaddr):
                    return True
        return False
    
    def packetArpSrcIp( self, message, ipaddr) :
        if self.packetIsARP(message):
            pkt = packet.Packet(message.data)
            a = pkt.get_protocol(arp.arp)
            if not cmp(a.src_ip, ipaddr):
                    return True
        return False
    
    def createArpRequest( self, message, ip):
        if not self.packetIsARP(message):
            print("Packet is not ARP")
            return
        pkt = packet.Packet(message.data)
        origarp = pkt.get_protocol(arp.arp)
        a = arp.arp(
            hwtype=origarp.hwtype,
            proto=origarp.proto,
            src_mac=origarp.src_mac,
            dst_mac=origarp.dst_mac,
            hlen=origarp.hlen,
            opcode=arp.ARP_REQUEST,
            plen=origarp.plen,
            src_ip=origarp.src_ip,
            dst_ip=ip
            )
        e = ethernet.ethernet(
            dst=mac.BROADCAST_STR,
            src=origarp.src_mac,
            ethertype=ether.ETH_TYPE_ARP)    
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()
        return p
    
    def createArpReply( self, message, ip):
        if not self.packetIsARP(message):
            print("Packet is not ARP")
            return
        pkt = packet.Packet(message.data)
        origarp = pkt.get_protocol(arp.arp)
        a = arp.arp(
            hwtype=origarp.hwtype,
            proto=origarp.proto,
            src_mac=origarp.src_mac,
            dst_mac=origarp.dst_mac,
            hlen=origarp.hlen,
            opcode=arp.ARP_REPLY,
            plen=origarp.plen,
            src_ip=ip,
            dst_ip=origarp.dst_ip
            )
        e = ethernet.ethernet(
            dst=origarp.dst_mac,
            src=origarp.src_mac,
            ethertype=ether.ETH_TYPE_ARP)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()
        return p
    
    def ipv4_to_int( self, string):
        ip = string.split('.')
        assert len(ip) == 4
        i = 0
        for b in ip:
            b = int(b)
            i = (i << 8) | b
        return i
    
    def sendPacketOut(  self, msg, actions, buffer_id=0xffffffff, data=None ):
        datapath = msg.datapath
        parser = datapath.ofproto_parser
    
        if buffer_id == 0xffffffff :
            out = parser.OFPPacketOut(
                datapath=datapath, buffer_id=buffer_id, in_port=msg.in_port,
                actions=actions, data=data)
            datapath.send_msg(out)
        else:
            out = parser.OFPPacketOut(
                datapath=datapath, buffer_id=buffer_id, in_port=msg.in_port,
                actions=actions)
            datapath.send_msg(out)
    
    def getFullMatch( self, msg, in_port ):
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        
        #in_port=None
        dl_src=None
        dl_dst=None
        dl_vlan=None
        dl_vlan_pcp=None
        dl_type=None
        nw_tos=None
        nw_proto=None
        nw_src=None
        nw_dst=None
        tp_src=None
        tp_dst=None
        
        #in_port = msg.in_port
        #in_port = msg.match['in_port']
        
        pkt = packet.Packet(msg.data)
    
        #eth = pkt.get_protocol(ethernet.ethernet)
        eth = pkt.get_protocols(ethernet.ethernet)
    
        dl_src = eth.src
        dl_dst = eth.dst
        #dl_type = eth.ethertype
    
        vl = pkt.get_protocol(vlan.vlan)
        if vl is not None :
            dl_vlan = vl.vid
            dl_vlan_pcp = vl.pcp
            #dl_type = vl.ethertype
        
        ip = pkt.get_protocol(ipv4.ipv4)
        if ip is not None :
            nw_src = ip.src
            nw_dst = ip.dst
            nw_proto = ip.proto
            nw_tos = ip.tos
    
            t = pkt.get_protocol(tcp.tcp)
            if t is not None :
                tp_src = t.src_port
                tp_dst = t.dst_port
    
            u = pkt.get_protocol(udp.udp)   
            if u is not None :
                tp_src = u.src_port
                tp_dst = u.dst_port
        
            ic = pkt.get_protocol(icmp.icmp)
            if ic is not None :
                tp_src = ic.type
                tp_dst = ic.code
        
        a = pkt.get_protocol(arp.arp)
        if a is not None :
            nw_src = a.src_ip
            nw_dst = a.dst_ip
            nw_proto = a.opcode
    
        match = parser.OFPMatch( 
            dl_src=mac.haddr_to_bin(dl_src), #dl_src,  
            dl_dst=mac.haddr_to_bin(dl_dst),  # dl_dst,
            #dl_vlan=dl_vlan, 
            #dl_vlan_pcp=dl_vlan_pcp, 
            #dl_type=dl_type, 
            #nw_tos=nw_tos, 
            #nw_proto=nw_proto, 
            #nw_src=self.ipv4_to_int(nw_src), 
            #nw_dst=self.ipv4_to_int(nw_dst), 
            #tp_src=tp_src, 
            #tp_dst=tp_dst,
            in_port=in_port)
        return match

    #

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
        
        #@Thien - testing
        #ipv4_test = pkt.get_protocols(ipv4.ipv4)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src
        
        #@Thien - testing
        #ipv4_src_addr = ipv4_test.src
        #ipv4_dst_addr = ipv4_test.dst 
        #

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        #@Thien - testing
        #self.logger.info("packet in %s %s %s %s", dpid, ipv4_src_addr, ipv4_dst_addr, in_port)
        #

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            
#@Thien: 2016-05-22
            match=None

            #nw_tos=None
            nw_src=None
            nw_dst=None
            nw_proto=None
            tp_src=None
            tp_dst=None
            
            ip = pkt.get_protocol(ipv4.ipv4)
            if ip is not None:
                nw_src = ip.src
                nw_dst = ip.dst
                nw_proto = ip.proto
                
                self.logger.info("ip_src=%s", nw_src)
                self.logger.info("ip_dst=%s", nw_dst)
                self.logger.info("ip_proto=%s", nw_proto)
                #nw_tos = ip.tos
    
                t = pkt.get_protocol(tcp.tcp)
                if t is not None:
                    tp_src = t.src_port
                    tp_dst = t.dst_port
        
                u = pkt.get_protocol(udp.udp) 
                if u is not None:
                    tp_src = u.src_port
                    tp_dst = u.dst_port
            
                ic = pkt.get_protocol(icmp.icmp)
                if ic is not None:
                    tp_src = ic.type
                    tp_dst = ic.code
#-------        
                match = parser.OFPMatch(ipv4_src=nw_src, ipv4_dst=nw_dst, ip_proto=nw_proto, eth_type=eth.ethertype)
                                        #tcp_src=tp.src_port, tcp_dst=tp.dst_port) 
                #match = parser.OFPMatch(in_port=in_port, ipv4_dst='192.168.1.101')#in_port=in_port, eth_src=src, eth_dst=dst
                                        
                self.logger.info("IPv4 packet:")
                
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions) 
                self.logger.info("New flow entry added to switch")
            
            else:
                self.logger.info("Not IPv4 packet: No flow entry added (ignored)")
                #return
            #match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst)
            #Thien-testing
            #match = self.getFullMatch(msg)
            #match = self.getFullMatch(msg, in_port)
            
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            
            #if msg.buffer_id != ofproto.OFP_NO_BUFFER:
            #    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
            #    return
            #else:
            #    self.add_flow(datapath, 1, match, actions)
            
            #self.logger.info("New flow entry added to switch")
                
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
