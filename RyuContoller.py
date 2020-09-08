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
import ryu.ofproto.ofproto_v1_3_parser as parser
import ryu.ofproto.ofproto_v1_3 as ofproto
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, ipv6 , arp, icmp
from ryu.lib.packet import ether_types
from ryu.lib.packet import tcp
import pickle, threading
import socket
from random import randint
import time

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    Hostnumber = 123
    Hostinfo =[]
    Data_Path = {}
    Flowcounter = {}
    Edgeswitch = [257,258,259,260]
    mac_to_port = {}
    Keys= {}
    newlocation =[]
    prevalueSPkt={}
    prevalueRPkt={}
    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        #self.mac_to_port = {}
         

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        self.Data_Path[dpid]= datapath
        self.Flowcounter.setdefault(dpid, 1)
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
        ip = pkt.get_protocol(ipv4.ipv4)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src
        #if pkt_tcp:# dpid in edge switches
        #   print pkt
        #   print "pak:", pkt_tcp.seq
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        #print self.mac_to_port.keys()
        # learn a mac address to avoid FLOOD next time.
        
        if ip and dpid in self.Edgeswitch:
          if (dpid, src, ip.src, in_port) in self.Hostinfo:
              print ip.src ,"is an authenticated user and its location", dpid,in_port
          else:
             print "Unauthenticated user"
             return
        else:
            self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
          

        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & pa enumerate(cket_out
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
    

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
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

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
           datapath = ev.msg.datapath
           ofp_parser = datapath.ofproto_parser
           ofproto = datapath.ofproto
           dpid = datapath.id
           l = [257,260]
           last_item = 32
           if dpid in l:
              last_item = 31
           for stat in ev.msg.body:
            if stat.port_no in range(2,last_item):
                self.prevalueSPkt.setdefault((dpid,stat.port_no), 0)
                self.prevalueRPkt.setdefault((dpid,stat.port_no), 0)
                Diffsend = stat.tx_packets - self.prevalueSPkt[dpid,stat.port_no]
                Diffrecive = stat.rx_packets - self.prevalueRPkt[dpid,stat.port_no]
                if Diffsend > Threshold:
                   for item in self.Hostinfo:
                     if dpid in item and stat.port_no in item:
                        Key = self.Diffie_Hellman(item[1])
                        match = ofp_parser.OFPMatch(eth_src = item[1], in_port = stat.port_no)
                        mod = ofp_parser.OFPFlowMod(datapath=datapath, priority=1,
                                 command=ofproto.OFPFC_DELETE,
                                 match=match)
                        datapath.send_msg(mod)
                        self.logger.info("Delete the flow entries which match port: %d and src: %d"%(stat.port_no,item[1]))
                        return 
                   (dpid, src, ip_src, in_port) in self.Hostinfo
                if Diffsend > Gratest: 

    def send_port_stats_request(self):
          for dpid in self.Edgeswitch:
               datapath = self.Data_Path[dpid]
               #Currently not waiting for switch to respond to previous request
               ofp = datapath.ofproto
               ofp_parser = datapath.ofproto_parser

            # ofp.OFPP_ANY sends request for all ports
               req = ofp_parser.OFPPortStatsRequest(datapath , 0, ofp.OFPP_ANY)
               datapath.send_msg(req)
               #print "states request of switch %d sent", dpid

    def send_flow_stats_request(self, item):
       datapath = self.Data_Path[item[0]]
       ofp = datapath.ofproto
       ofp_parser = datapath.ofproto_parser

       cookie = cookie_mask = 0
       match = ofp_parser.OFPMatch(in_port=in_port, eth_src=item[2])
       req = ofp_parser.OFPFlowStatsRequest(datapath, 0,ofp.OFPTT_ALL,ofp.OFPP_ANY, ofp.OFPG_ANY,cookie, cookie_mask,match)
       datapath.send_msg(req) 

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
      datapath = ev.msg.datapath
      dpid = datapath.id
      for stat in ev.msg.body:
        if stat.packet_count > 0 :    
           src = stat.match['eth_src']
           in_port = stat.match['in_port']
           for item in self.newlocation:
             if src in item and in_port in item:
                self.newlocation.remove(item)
                for index, anitem in enumerate(self.Hostinf):
                  if src in anitem and in_port in anitem and dpid in anitem:
                         ip_src = self.Hostinf[index][2]
                         self.Hostinf[index]= (dpid, src, ip_src, in_port)
                         print ip_src,"changed his location to", dpid, in_port

    def Diffie_Hellman(self, src):
        G = 15
        p = 21841
        a = randint(0,10000)
        Public_Key = G**a % p
        self.Keys[src] = (public_Key, None)# sending Msg to src with a public Key
        for i in range(1,30):
          t_end = time.time() + 1
          while time.time() < t_end:
             pass
          if self.Key[src][1] != None:
                 Private_key = self.Key[src][1]**a % p
                 return Private_key
        return 0
                 

class ThreadingExample(SimpleSwitch13):
    """ Threading example class
    The run() method will be started and it will run in the background
    until the application exits.
    """

    def __init__(self):
        """ Constructor
        """
        thread = threading.Thread(target=self.foo, args=())
        thread.daemon = True                            # Daemonize thread
        thread.start()

    def Checkthenewlocation(self):
       while True:
          time.sleep(3)
          if len(self.newlocation) > 0:
            for item in self.newlocation:
               self.send_flow_stats_request(item)
          else:
            print "No host changed his posation"
            

    def monitor_port(self):
          time.sleep(30)
          while True:
               self.send_port_stats_request()
               time.sleep(3)

    def foo(self):
            #buffer_id = 4294967295
            #s = socket.socket()         # Create a socket object
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            #host = socket.gethostname()   # Get local machine name
            port = 5001                   # Reserve a port for your service.
            s.bind(('', port))             # Bind to the port
            s.listen(1000)                 # Now wait for client connection.
            while True:
                  c, addr = s.accept()     # Establish connection with client.
                  print 'Got connection from', addr
                  #rdata =json.loads(c.recv(2048))
                  rdata = pickle.loads(c.recv(1024))
                  if not rdata:
                      break
                  #print 'New user', rdata
                  #c.send('Thank you for connecting')
                  dpid = rdata[0]
                  src = rdata[1]
                  dst = rdata[2]
                  in_port = rdata[3]#MacAddress
                  ip_src = rdata[4]
                  buffer_id = rdata[5]
                  msg_data = rdata[6]
                  if rdata[7]:
                     mpls = rdata[7]
                  datapath = self.Data_Path[dpid]

                  if not mpls:
                    if (dpid, src, ip_src, in_port) in self.Hostinfo:
                       pass
                    elif len(self.Hostinfo) >= self.Hostnumber :
                      print "BLOCK"
                      self.logger.info("packet in Socket %s %s %s %s", dpid, src, dst, in_port)
                      actions = []
                      match = parser.OFPMatch(in_port=in_port)
                      self.add_flow(datapath, 10, match, in_port , actions)
                      return
                    else:
                      print "new item"
                      self.Hostinfo.append((dpid, src, ip_src, in_port))
                  else:
                    Key = self.Diffie_Hellman(src)
                    self.newlocation.append((dpid, src, ip_src, in_port))

                  self.mac_to_port[dpid][src] = in_port

                  if dst in self.mac_to_port[dpid]:
                     out_port = self.mac_to_port[dpid][dst]
                  else:
                    out_port = ofproto.OFPP_FLOOD

                  actions = [parser.OFPActionOutput(out_port)]

                  # install a flow to avoid packet_in next time
                  if out_port != ofproto.OFPP_FLOOD:
                    if key:
                         match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src, eth_type=0x8847,mpls_label=key)
                    else:
                         match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                   # verify if we have a valid buffer_id, if yes avoid to send both
                    # flow_mod & packet_out
                    if buffer_id != ofproto.OFP_NO_BUFFER:
                      self.add_flow(datapath, 1, match, actions, buffer_id)
                      return
                    else:
                      self.add_flow(datapath, 1, match, actions)
                  data = None
                  if buffer_id == ofproto.OFP_NO_BUFFER:
                     data = msg_data

                  out = parser.OFPPacketOut(datapath=datapath, buffer_id=buffer_id,
                                  in_port=in_port, actions=actions, data=data)
                  datapath.send_msg(out)    
example = ThreadingExample()                
