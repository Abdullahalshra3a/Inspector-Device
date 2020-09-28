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
from ryu.lib.packet import ethernet, ipv4, ipv6 , arp, icmp
from ryu.lib.packet import ether_types
from ryu.lib.packet import tcp
import pickle, threading
import socket    



class inspector(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    Hostnumber = 123
    Hostinfo = []

    def __init__(self, *args, **kwargs):
        super(inspector, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [ parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
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
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        ip = mpls = False
        ip = pkt.get_protocol(ipv4.ipv4)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignorHostinfo.appende lldp packet
            return
        dst = eth.dst
        src = eth.src       
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        

        l = [257,260]
        last_item = 32
        if dpid in l:
           last_item = 31
 
        if ip and in_port in range(2,last_item + 1):
          if (dpid, src, ip.src, in_port) in self.Hostinfo:
               return              
          elif len(self.Hostinfo) >= self.Hostnumber :
             for item in self.Hostinfo :
                if ip.src in item and src in item:
                  mpls = True
                  Tuple = (dpid, src, dst, in_port, ip.src, msg.buffer_id, msg.data, mpls)
                  y = pickle.dumps(Tuple)
                  self.sendToC1(y)
                  print ip.src, "changed its location from", item[0],item[3], "To", dpid, in_port
                  return
             if mpls == False:
                  self.logger.info(" BLOCK %s %s %s %s", dpid, src, dst, in_port)
                  Tuple = (dpid, src, dst, in_port, ip.src, msg.buffer_id, msg.data, mpls)
                  y = pickle.dumps(Tuple)
                  self.sendToC1(y)
                  print ip.src, "changed its location from", item[0],item[3], "To", dpid, in_port
                  return
          else:
            print "new item", len(self.Hostinfo)
            self.Hostinfo.append((dpid, src, ip.src, in_port))
            print self.Hostinfo
            Tuple = (dpid, src, dst, in_port, ip.src, msg.buffer_id, msg.data)
            y = pickle.dumps(Tuple)
            self.sendToC1(y)
            self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        
    def sendToC1(self, y):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        host = socket.gethostname() # Get local machine name
        port = 5001                # Reserve a port for your service.
        s.connect((host, port))
        s.sendall(y)
        #print s.recv(1024)
        s.close
