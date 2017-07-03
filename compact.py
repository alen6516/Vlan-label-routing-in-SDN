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
from ryu.lib.packet import ethernet,arp,ipv4,icmp
from ryu.lib.packet import ether_types

from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link

from mapping import host_number
from mapping import host_list
from mapping import mapping_list

dp_list=[]

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.topology_api_app = self
    
    # when a new switch is connected
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        switch_obj_list = get_switch(self.topology_api_app, None)
        
        del dp_list[:]
        for switch in switch_obj_list:
            dp_list.append(switch.dp)

        link_obj_list = get_link(self.topology_api_app, None)
        
        for dp in dp_list:    
            self.logger.info('dpid=%s' % dp.id)
        

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
        '''
        match_1 = parser.OFPMatch(eth_dst='00:00:00:00:00:02')
        action_1 = [parser.OFPActionOutput(3)]
        self.add_flow(datapath, 1, match_1, action_1)

        match_2 = parser.OFPMatch(eth_dst='00:00:00:00:00:01')
        action_2 = [parser.OFPActionOutput(2)]
        self.add_flow(datapath, 1, match_2, action_2)
        '''

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        self.logger.info('in add_flow')
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
        self.logger.info('mod=%s' % mod)
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
        pkt_eth = pkt.get_protocol(ethernet.ethernet)
        if not pkt_eth:
            return
        pkt_arp = pkt.get_protocol(arp.arp)
        if pkt_arp:
            self.logger.info("arp packet in, dpid=%s, port=%s, src=%s, dst=%s" % (datapath.id, in_port, pkt_arp.src_ip, pkt_arp.dst_ip))
            self._handle_ingress_arp(datapath, in_port, pkt_eth, pkt_arp)
            return
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_icmp = pkt.get_protocol(icmp.icmp)
        if pkt_icmp:
            pass
            self.logger.info("icmp packet in, dpid=%s, port=%s, src=%s, dst=%s" % (datapath.id, in_port, pkt_ipv4.src, pkt_ipv4.dst))
            self._handle_ingress_icmp(datapath, in_port, pkt_eth, pkt_ipv4, pkt_icmp)
            return
    

    def _handle_ingress_arp(self, datapath, in_port, pkt_eth, pkt_arp):
        if pkt_arp.opcode!=arp.ARP_REQUEST:
            return
        self.logger.info("in arp handler")
        for host in host_list:
            if host.ip==pkt_arp.dst_ip:
                temp_host=host
        
        self.logger.info('select host.ip=%s, host.mac=%s' % (temp_host.ip, temp_host.mac))
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=pkt_eth.ethertype,
                                            dst=pkt_eth.src,
                                            src=temp_host.mac))
        pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                src_mac=temp_host.mac,
                                src_ip=temp_host.ip,
                                dst_mac=pkt_arp.src_mac,
                                dst_ip=pkt_arp.src_ip))
        self._send_packet(datapath, in_port, pkt)

    def _handle_ingress_icmp(self, datapath, in_port, pkt_eth, pkt_ipv4, pkt_icmp):
        parser = datapath.ofproto_parser

        src_dpid=datapath.id

        src_ip = pkt_ipv4.src
        dst_ip = pkt_ipv4.dst
        src_mac = pkt_eth.src
        dst_mac = pkt_eth.dst
        protocol='icmp'
       
        entry = self.get_entry(protocol, src_ip, src_mac, dst_ip, dst_mac) 
        vlan_id = int(entry.vlan)
        
        self.logger.info('match entry.protocol=%s, entry.src_ip=%s, dst_ip=%s, src_mac=%s, dst_mac=%s, vlan=%s' % (entry.protocol, entry.src_ip, entry.dst_ip, entry.src_mac, entry.dst_mac, entry.vlan))
       
        match = parser.OFPMatch(eth_type=0x0800,
                                eth_dst=dst_mac,
                                eth_src=src_mac,
                                ipv4_src=src_ip,
                                ipv4_dst=dst_ip)

        match_vlan = parser.OFPMatch(vlan_vid=(0x1000|vlan_id))

        if int(src_dpid)==1:
            if int(dst_mac[-1])<=host_number//2:
                if dst_mac=='00:00:00:00:00:01':
                    action = [parser.OFPActionOutput(2)]
                elif dst_mac=='00:00:00:00:00:02':
                    action = [parser.OFPActionOutput(3)]
                elif dst_mac=='00:00:00:00:00:03':
                    action = [parser.OFPActionOutput(4)]
                self.add_flow(datapath, 1, match, action)
            else:
                action_1 = [parser.OFPActionPushVlan(),parser.OFPActionSetField(vlan_vid=vlan_id),parser.OFPActionOutput(1)]
                action_2 = [parser.OFPActionOutput(2)]
                action_3 = [parser.OFPActionPopVlan()]
                if dst_mac=='00:00:00:00:00:04':
                    action_3.append(parser.OFPActionOutput(2))
                elif dst_mac=='00:00:00:00:00:05':
                    action_3.append(parser.OFPActionOutput(3))
                elif dst_mac=='00:00:00:00:00:06':
                    action_3.append(parser.OFPActionOutput(4))
                
                datapath_2=self.get_datapath(2)
                datapath_3=self.get_datapath(3)
                
                self.add_flow(datapath, 1, match, action_1)
                #self.add_flow(datapath_2, 1, match, action_2)
                #self.add_flow(datapath_2, 1, match_vlan, [parser.OFPActionOutput(2)])
                self.add_flow(datapath_2, 1, match_vlan, action_2)
                self.add_flow(datapath_3, 1, match, action_3)
                
                
        elif int(src_dpid)==3:
            if int(dst_mac[-1])>host_number//2:
                if dst_mac=='00:00:00:00:00:04':
                    action = [parser.OFPActionOutput(2)]
                elif dst_mac=='00:00:00:00:00:05':
                    action = [parser.OFPActionOutput(3)]
                elif dst_mac=='00:00:00:00:00:06':
                    action = [parser.OFPActionOutput(4)]
                self.add_flow(datapath, 1, match, action)
            else:
                action_1 = [parser.OFPActionPushVlan(),parser.OFPActionSetField(vlan_vid=vlan_id),parser.OFPActionOutput(1)]
                action_2 = [parser.OFPActionOutput(1)]
                action_3 = [parser.OFPActionPopVlan()]
                if dst_mac=='00:00:00:00:00:01':
                    action_3.append(parser.OFPActionOutput(2))
                elif dst_mac=='00:00:00:00:00:02':
                    action_3.append(parser.OFPActionOutput(3))
                elif dst_mac=='00:00:00:00:00:03':
                    action_3.append(parser.OFPActionOutput(4))
                
                datapath_2=self.get_datapath(2)
                datapath_3=self.get_datapath(1)
                
                self.add_flow(datapath, 1, match, action_1)
                #self.add_flow(datapath_2, 1, match, action_2)
                #self.add_flow(datapath_2, 1, match_vlan, [parser.OFPActionOutput(1)])
                self.add_flow(datapath_2, 1, match_vlan, action_2)
                self.add_flow(datapath_3, 1, match, action_3)
        
    def _send_packet(self, datapath, in_port, pkt):
        self.logger.info('in send packet')

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        data = pkt.data
        actions = [parser.OFPActionOutput(port=in_port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                buffer_id=ofproto.OFP_NO_BUFFER,
                                in_port=ofproto.OFPP_CONTROLLER,
                                actions=actions,
                                data=data)
        datapath.send_msg(out)
        
    def get_datapath(self, dpid):
        for dp in dp_list:
            if int(dp.id)==dpid:
                return dp
    def get_entry(self, protocol, src_ip, src_mac, dst_ip, dst_mac):
        for entry in mapping_list:
            if entry.src_ip==src_ip and\
                entry.dst_ip==dst_ip and\
                entry.src_mac==src_mac and\
                entry.dst_mac==dst_mac and\
                entry.protocol==protocol:
                return entry
    def get_vlan_id(self, entry):
        return entry.vlan
        
