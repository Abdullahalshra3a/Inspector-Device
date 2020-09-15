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
import pickle, threading , Inspector
import socket
from random import randint
import time

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    Hostnumber = 123
    Data_Path = {}
    Flowcounter = {}
    Edgeswitch = [257,258,259,260]
    mac_to_port = {}
    Keys= {}
    newlocation =[]
    prevalueSPkt={}
    prevalueRPkt={}
    SlowAttack = False
    Threshold_tx = Threshold_rx = counter = Gratest_rx = Gratest_tx = 0
    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        #self.mac_to_port = {}
        start_time = time.time()
         

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
        if dpid in self.Edgeswitch:
           self.add_tcp_table(datapath)
           match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_flags=2)
           actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
           self.add_flow(datapath, 1, match, actions, table_id=0)


    def add_flow(self, datapath, priority, match, actions, buffer_id=None, table_id=1):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [ parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority,table_id=table_id, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,table_id=table_id,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def add_tcp_table(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionGotoTable(1)]
        mod = parser.OFPFlowMod(datapath=datapath, table_id=0, priority=0, instructions=inst)
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
        self.Key.setdefault(src, (None,None)) 
        if self.Key[src][1] != None:
            Private_key = self.Key[src][1]**a % p

        if ip and dpid in self.Edgeswitch:
          if (dpid, src, ip.src, in_port) in Inspector.Hostinfo:
            if msg.table_id == 0 and pkt_tcp.seq == 2:
               if Private_key:
                      match = parser.OFPMatch(in_port=in_port, eth_type=0x0800, ip_proto=6, tcp_flags=2, eth_type=0x8847,mpls_label=Private_key)
                      priority = 10
                      inst = [parser.OFPInstructionGotoTable(1)]
                      mod = parser.OFPFlowMod(datapath=datapath, table_id=0, priority=0, instructions=inst)
                      datapath.send_msg(mod)
                      actions = []
                      match = parser.OFPMatch(in_port =in_port, eth_type=0x0800, ip_proto=6, tcp_flags=2)
                      self.add_flow(datapath, 5, match, actions, table_id = 0)
                      return
                else:
                      match = parser.OFPMatch(in_port =in_port, eth_type=0x0800, ip_proto=6, tcp_flags=2)
                      priority = 10
                      inst = [parser.OFPInstructionGotoTable(1)]
                      mod = parser.OFPFlowMod(datapath=datapath, table_id=0, priority=0, instructions=inst)
                      datapath.send_msg(mod)
                      return
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
        priority = 1
        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            if Private_key:
               match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src, eth_type=0x8847,mpls_label=Private_key)
               priority = 10
               self.Add_bloked_flow(datapath, in_port,src)
            else:
               match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & pa enumerate(cket_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, priority, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, priority, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
    

    def add_block_flow(self,in_port, src):
          match = parser.OFPMatch(in_port=in_port, eth_src=src)
          actions = []
          self.add_flow(datapath, 1, match, actions)

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
                self.counter = +1
                self.prevalueSPkt.setdefault((dpid,stat.port_no), 0)
                self.prevalueRPkt.setdefault((dpid,stat.port_no), 0)
                Diffsend = stat.tx_packets - self.prevalueSPkt[dpid,stat.port_no]
                Diffrecive = stat.rx_packets - self.prevalueRPkt[dpid,stat.port_no] #we could use this part to slow attack
                if Diffrecive > self.Threshold_rx and (time.time() - self.start_time) > 30 :
                  for item in Inspector.Hostinfo:
                     if dpid in item and stat.port_no in item:
                        self.Slow_attack = True
                        cookie = cookie_mask = 0
                        match = ofp_parser.OFPMatch(eth_dst=item[2])
                        req = ofp_parser.OFPFlowStatsRequest(datapath, 0,ofp.OFPTT_ALL,ofp.OFPP_ANY, ofp.OFPG_ANY,cookie, cookie_mask,match)
                        datapath.send_msg(req)
                if Diffsend > self.Threshold_tx and (time.time() - self.start_time) > 30 :
                   for item in Inspector.Hostinfo:
                     if dpid in item and stat.port_no in item:
                        self.Diffie_Hellman(item[1])
                        match = ofp_parser.OFPMatch(eth_src = item[1], in_port = stat.port_no)
                        mod = ofp_parser.OFPFlowMod(datapath=datapath, priority=1,command=ofproto.OFPFC_DELETE,match=match)
                        datapath.send_msg(mod)
                        self.logger.info("Delete the flow entries which match in_port: %d and src: %d", stat.port_no,item[1])
                        #return 
                if Diffsend > Gratests_tx:
                     self.Gratest_tx = Diffsend
               
                if Diffrecive > Gratest_rx:
                     self.Gratest_rx = Diffsend
 
           
            if counter >= self.Hostnumber:
                 if self.Threshold_tx == 0:
                   self.Threshold_tx = self.Gratest_tx * 1.5
                 else:
                   self.Threshold_tx = (self.Threshold_tx * 0.95 + self.Gratest_tx * 0.5) * 1.5

                 if self.Threshold_rx == 0:
                   self.Threshold_rx = self.Gratest_rx * 1.5
                 else:
                   self.Threshold_rx = (self.Threshold_rx * 0.95 + self.Gratest_rx * 0.5) * 1.5 

                         
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
       match = ofp_parser.OFPMatch(in_port=item[3], eth_src=item[1])
       req = ofp_parser.OFPFlowStatsRequest(datapath, 0,ofp.OFPTT_ALL,ofp.OFPP_ANY, ofp.OFPG_ANY,cookie, cookie_mask,match)
       datapath.send_msg(req) 

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
      datapath = ev.msg.datapath
      dpid = datapath.id
     if len(self.newlocation) > 0:       
      for stat in ev.msg.body:
          src = stat.match['eth_src']
          in_port = stat.match['in_port']
          for item in self.newlocation:
            if src in item and in_port in item:
              if stat.packet_count > 0:    
                self.newlocation.remove(item)
                for index, anitem in enumerate(self.Hostinf):
                  if src in anitem:
                         del self.mac_to_port[item[0]][item[1]]
                         ip_src = self.Hostinf[index][2]
                         self.Hostinf[index]= (dpid, src, ip_src, in_port)
                         self.mac_to_port[dpid][src]=in_port
                         print ip_src,"changed his location to", dpid, in_port
                         for datapath in self.Data_Path:
                             match = ofp_parser.OFPMatch(eth_dst = item[1])
                             mod = ofp_parser.OFPFlowMod(datapath=datapath, priority=1,command=ofproto.OFPFC_DELETE,match=match)
                             datapath.send_msg(mod)
     elif self.SlowAttack:
      if len(self.A) == 0:
         for stat in ev.msg.body:
            src = stat.match['eth_src']
            self.A[src]= stat.packet_count
         time.sleep(1)
         cookie = cookie_mask = 0
         match = ofp_parser.OFPMatch(eth_dst=item[2])
         req = ofp_parser.OFPFlowStatsRequest(datapath, 0,ofp.OFPTT_ALL,ofp.OFPP_ANY, ofp.OFPG_ANY,cookie, cookie_mask,match)
         datapath.send_msg(req)
      else:
         for stat in ev.msg.body:
            src = stat.match['eth_src']
            if len(self.A[src]) > 0 and (stat.packet_count - self.A[src]) > 0:
               for item in self.Hostinf:
                    if src in item:
               self.Diffie_Hellman(src)
               datapath = self.Data_Path[item[0]]
               match = ofp_parser.OFPMatch(eth_src = src, in_port = item[3])
               mod = ofp_parser.OFPFlowMod(datapath=datapath, priority=1,command=ofproto.OFPFC_DELETE,match=match)
               datapath.send_msg(mod)
               self.logger.info("Delete the flow entries which match port: %d and src: %d", item[3],item[1])
          self.SlowAttack = False
          self.A = []
     else:#tcp
        C = {}
        for stat in ev.msg.body:
          src = stat.match['eth_src']
          in_port = stat.match['in_port']
          C[src,in_port]= +stat.packet_count
        for key in C.keys():
          self.prevalue_tcp.setdefault(state.match, 0)
          Difftcp = stat.packet_count - self.prevaluetcp[stat.match]
          in_port = stat.match['in_port'] ]
          if stat.packet_count > self.Threshold_tcp
                         
                for index, anitem in enumerate(self.Hostinf):
                  if src in anitem:
                         del self.mac_to_port[item[0]][item[1]]
                         ip_src = self.Hostinf[index][2]
                         self.Hostinf[index]= (dpid, src, ip_src, in_port)
                         self.mac_to_port[dpid][src]=in_port
                         print ip_src,"changed his location to", dpid, in_port
                         for datapath in self.Data_Path:
                             match = ofp_parser.OFPMatch(eth_dst = item[1])
                             mod = ofp_parser.OFPFlowMod(datapath=datapath, priority=1,command=ofproto.OFPFC_DELETE,match=match)
                             datapath.send_msg(mod)
        
         
    def Diffie_Hellman(self, src):
        G = 15
        p = 21841
        a = randint(0,10000)
        Public_Key = G**a % p
        self.Keys[src] = (public_Key, None)# sending Msg to src with a public Key
    """
        for i in range(1,30):
          t_end = time.time() + 1
          while time.time() < t_end:
             pass
          if self.Key[src][1] != None:
                 Private_key = self.Key[src][1]**a % p
                 return Private_key
        return 0
                 
    """
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
          elif not self.SlowAttack:
            for dpid in self.Edgeswitch:
               datapath = self.Data_Path[dpid]
               ofp = datapath.ofproto
               ofp_parser = datapath.ofproto_parser

               cookie = cookie_mask = 0
               match = ofp_parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_flags=2)
               req = ofp_parser.OFPFlowStatsRequest(datapath, 0,ofp.OFPTT_ALL,ofp.OFPP_ANY, ofp.OFPG_ANY,cookie, cookie_mask,match)
               datapath.send_msg(req)
            

    def monitor_port(self):
          #time.sleep(30)
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
             
                  datapath = self.Data_Path[dpid]

                  if len(rdata) < 8:
                    self.mac_to_port[dpid][src] = in_port
                       pass # to Install an entry                 
                  elif rdata[7] == True:
                    Key = self.Diffie_Hellman(src)#should be thread
                    self.newlocation.append((dpid, src, ip_src, in_port))
                  else:
                    self.logger.info("BLOCK %s %s %s %s", dpid, src, dst, in_port)
                    actions = []
                    match = parser.OFPMatch(in_port=in_port)
                    self.add_flow(datapath, 10, match, in_port , actions)
                    return

                  

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
