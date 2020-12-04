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
import pickle, threading, os 
import socket
import ast
from random import randint
import time, psutil
class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    Hostnumber = 12
    Data_Path = {}
    Flowcounter = {}
    Edgeswitch = [257,258,259,260]
    mac_to_port = {}# here, the inheritor class reaches it
    Key = {}
    Cal = {}
    newlocation = []
    Hostinfo =[]
    A = {} # Includes the suspect users who could have lunched a Slow attack
    Memory = []
    CPU = []
    prevalueSPkt= {}
    prevaluetcp = {}
    prevalueRPkt={}
    SlowAttack = False
    Trainingtime = 90
    Threshold_tx = 150
    Threshold_rx = 150
    Threshold_tcp = 10
    counter = 0
    tcpcounter = 0
    Gratest_tcp = 0
    Gratest_rx =0
    Gratest_tx = 0
    Slow_attack = None
    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        #self.mac_to_port = {}
        self.start_time = time.time()
        Keyfile = open ('Key.txt', 'w')
        Keyfile.write(str(self.Key))
        Keyfile.close

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
        
        if dpid in self.Edgeswitch:
           self.add_tcp_table(datapath)
           match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_flags=2)
           actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
           self.add_flow(datapath, 1, match, actions,table_id = 0, idle_timeout=0, hard_timeout=0)
           match = parser.OFPMatch()
           actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
           self.add_flow(datapath, 0, match, actions, table_id = 1, idle_timeout=0, hard_timeout=0)
        else:
           match = parser.OFPMatch()
           actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
           self.add_flow(datapath, 0, match, actions,table_id = 0,  idle_timeout=0, hard_timeout=0)



    def add_flow(self, datapath, priority, match, actions, buffer_id=None, table_id=1, idle_timeout=120, hard_timeout=120):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,idle_timeout=idle_timeout, hard_timeout=hard_timeout,
                                    priority=priority,table_id=table_id, match=match,instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath,idle_timeout=idle_timeout, hard_timeout=hard_timeout, priority=priority,table_id=table_id,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
        self.Flowcounter[datapath.id] += 1

    def add_tcp_table(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionGotoTable(1)]
        match = parser.OFPMatch()
        mod = parser.OFPFlowMod(datapath=datapath, table_id=0, priority=0, match = match, idle_timeout=0, hard_timeout=0, instructions=inst)
        datapath.send_msg(mod)
        self.Flowcounter[datapath.id] += 1

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

        dpid = datapath.id
        
        self.mac_to_port.setdefault(dpid, {})

        # learn a mac address to avoid FLOOD next time.
        Private_key = 0
        table_id = 1
        #l = [257,260]
        last_item = 4 # we have to assign the correct user ports
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        priority = 1              
        if ip and dpid in self.Edgeswitch and in_port in range(2,last_item + 1):
            if (dpid, src, ip.src, in_port) in self.Hostinfo:
              if src in self.Key.keys():
                 file = open("/home/abdullah/ryu/Key.txt", "r")
                 contents = file.read()
                 dictionary = ast.literal_eval(contents)
                 file.close()
                 self.Key = dictionary                                                  
                 if self.Key[src][1]!= 0:# I have to waite the user answer                
                   t = self.Key[src]
                   lst = list(t)
                   lst[3] = lst[1]**lst[2] % 21841 #private key
                   t = tuple(lst)
                   self.Key[src] = t
                   Private_key = lst[3]
                 else:
                   return                                                     
              print ip.src ,"is an authenticated user and its location", dpid,in_port
            else:
               return
            if msg.table_id == 0 and pkt_tcp.bits == 2:
               if Private_key != 0 :
                      match = parser.OFPMatch(in_port=in_port, eth_src = src,  eth_type=0x8847,mpls_label=Private_key)
                      actions = [parser.OFPActionPopMpls(), parser.OFPActionOutput(out_port)]
                      inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                      mod = parser.OFPFlowMod(datapath=datapath, table_id=0, priority=10, match = match, instructions=inst)
                      datapath.send_msg(mod)
                      self.Flowcounter[dpid] += 1
                      actions = []
                      match = parser.OFPMatch(in_port =in_port, eth_type=0x0800, ip_proto=6, tcp_flags=2)
                      self.add_flow(datapath, 5, match, actions, table_id = 0)
                      return
               else:
                      match = parser.OFPMatch(in_port =in_port, eth_type=0x0800, ip_proto=6, tcp_flags=2)
                      actions = [parser.OFPActionOutput(out_port)]
                      inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                      mod = parser.OFPFlowMod(datapath=datapath, table_id=0, priority=10, match = match, instructions=inst)
                      datapath.send_msg(mod)
                      self.Flowcounter[dpid] += 1
                      print pkt
                      return
        elif dpid in self.Edgeswitch:
            self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
            table_id = 1
        else:
            self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
            table_id = 0
        
        
        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:            
            if Private_key != 0 and dpid in self.Edgeswitch:
               match = parser.OFPMatch(in_port=in_port, eth_src=src)
               actions = []
               self.add_flow(datapath, 5, match, actions, table_id = 1)               
               match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src, eth_type=0x8847,mpls_label=Private_key)
               priority = 10
               table_id = 1
               actions = [parser.OFPActionPopMpls(), parser.OFPActionOutput(out_port)]             
            else:
               match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & pa enumerate(cket_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, priority, match, actions, msg.buffer_id, table_id = table_id )
                return
            else:
                self.add_flow(datapath, priority, match, actions, table_id = table_id )          
        else:
            pass 
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
           ofp = ofproto
           dpid = datapath.id
           last_item = 4 #32 if dpid in [257,260] else 33
           for stat in ev.msg.body:
            if stat.port_no in range(2,last_item + 1):
                self.counter += 1
                self.prevalueSPkt.setdefault((dpid,stat.port_no), 0)
                self.prevalueRPkt.setdefault((dpid,stat.port_no), 0)
                Diffsend = stat.tx_packets - self.prevalueSPkt[dpid,stat.port_no]
                Diffrecive = stat.rx_packets - self.prevalueRPkt[dpid,stat.port_no] #we could use this part to slow attack
                self.prevalueSPkt[dpid,stat.port_no] = stat.tx_packets
                self.prevalueRPkt[dpid,stat.port_no] = stat.rx_packets
                if Diffsend > self.Threshold_tx and (time.time() - self.start_time) > self.Trainingtime :      
                    pass
                    """
                    for item in self.Hostinfo:
                     if dpid in item and stat.port_no in item:
                        self.Slow_attack = item[1]# determine the destination under attack
                        self.logger.info("Slow attack is Detected in switch %d port number %d ", dpid, stat.port_no)
                        cookie = cookie_mask = 0
                        match = ofp_parser.OFPMatch(eth_dst=item[1])
                        table_id = 1
                        req = ofp_parser.OFPFlowStatsRequest(datapath, 0, ofp.OFPTT_ALL,ofp.OFPP_ANY, ofp.OFPG_ANY,cookie, cookie_mask,match, table_id)
                        datapath.send_msg(req)
                        break
                    """
                if Diffrecive > round(self.Threshold_rx * 2) + 250 and (time.time() - self.start_time) > self.Trainingtime :
                   for item in self.Hostinfo:
                     if dpid in item and stat.port_no in item:
                        src = item[1]
                        if src in self.Key.keys():
                           #if self.Key[src][3]!=0:
                              #print src,"self.Key[src][3]", self.Key[src]
                              break
                        match = ofp_parser.OFPMatch(eth_src = src, in_port = stat.port_no)
                        mod = ofp_parser.OFPFlowMod(datapath=datapath, table_id=1, priority=1, command=ofproto.OFPFC_DELETE, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY, match=match)
                        datapath.send_msg(mod)
                        print Diffrecive , round(self.Threshold_rx * 2) + 50
                        print "Delete the flow entries which match in_port: %d and src: %s"%(stat.port_no,item[1])
                        self.Diffie_Hellman(item[1])#exchange Public keys                                               
                        break 
    
                if Diffsend > self.Gratest_tx:
                     self.Gratest_tx = Diffsend 
                if Diffrecive > self.Gratest_rx:
                     self.Gratest_rx = Diffsend

           if self.counter >= self.Hostnumber and (time.time() - self.start_time) > 10:                 
                   self.Threshold_tx = (self.Threshold_tx * 0.95) + (self.Gratest_tx * 0.05) 

                   self.Threshold_rx = (self.Threshold_rx * 0.95) + (self.Gratest_rx * 0.05)  
                   self.Gratest_tx = 50
                   self.Gratest_rx = 50
                   self.counter = 0
                   file = open ('Y.txt', 'a')
                   file.write(str(self.Threshold_rx))
                   file.close 
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
       table_id = 1
       req = ofp_parser.OFPFlowStatsRequest(datapath, 0, ofp.OFPTT_ALL,ofp.OFPP_ANY, ofp.OFPG_ANY,cookie, cookie_mask,match, table_id)
       datapath.send_msg(req) 

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
      datapath = ev.msg.datapath
      dpid = datapath.id
      ofp_parser = datapath.ofproto_parser
      ofp = datapath.ofproto

      for stat in ev.msg.body:        
        if stat.table_id == 0:#SYN_Attack 
          if stat.priority == 10:
            in_port = stat.match['in_port']
            self.prevaluetcp.setdefault((dpid , in_port), 0)
            Difftcp = stat.packet_count - self.prevaluetcp[dpid , in_port]
            self.prevaluetcp[dpid , in_port] = stat.packet_count
            if Difftcp > round(self.Threshold_tcp * 2) + 15 and (time.time() - self.start_time) > self.Trainingtime:             
              for i in range(50):
                      print "attack", self.Threshold_tcp, Difftcp, self.Gratest_tcp 
              for item in self.Hostinfo:
                if dpid in item and in_port in item:
                   src = item[1]
                   if src in self.Key.keys():
                      break
                   
                   self.Diffie_Hellman(src)
                   print "SYN ATTACK Delete the flow entries which match in_port: %d and src: %s" %(in_port,item[1]) 
                   match = ofp_parser.OFPMatch(in_port = in_port)
                   mod = ofp_parser.OFPFlowMod(datapath=datapath, table_id=0, priority=10,command=ofproto.OFPFC_DELETE,out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,match=match)
                   datapath.send_msg(mod)
            else:
                 if Difftcp > self.Gratest_tcp:
                     self.Gratest_tcp = Difftcp



        elif len(self.newlocation) > 0:
          if stat.priority > 0:
            src = stat.match['eth_src']
            in_port = stat.match['in_port']
            for item in self.newlocation:
              if src in item and in_port in item:
                if stat.packet_count > 0:    
                  self.newlocation.remove(item)
                  for index, anitem in enumerate(self.Hostinfo):
                    if src in anitem:
                         del self.mac_to_port[item[0]][item[1]]
                         ip_src = self.Hostinfo[index][2]
                         self.Hostinfo[index]= (dpid, src, ip_src, in_port)
                         self.mac_to_port[dpid][src]=in_port
                         print ip_src,"changed his location to", dpid, in_port
                         for datapath in self.Data_Path:
                             match = ofp_parser.OFPMatch(eth_dst = item[1])
                             mod = ofp_parser.OFPFlowMod(datapath=datapath, table_id=1, command=ofproto.OFPFC_DELETE,match=match)
                             datapath.send_msg(mod)
        else:#slowattack
         pass
         """
         if len(self.A) == 0:
             if stat.priority > 0:
               src = stat.match['eth_src']
               self.A[src]= stat.packet_count
               dst = stat.match['eth_dst']               
         else:
                if stat.priority > 0:
                  src = stat.match['eth_src']                                
                  if src in self.A and (stat.packet_count - self.A[src]) > 0:
                    for item in self.Hostinfo:
                       if src in item:
                          break
                          self.Diffie_Hellman(src)
                          datapath = self.Data_Path[item[0]]
                          match = ofp_parser.OFPMatch(eth_src = src, in_port = item[3])
                          mod = ofp_parser.OFPFlowMod(datapath=datapath, table_id=1, command=ofproto.OFPFC_DELETE,match=match)
                          datapath.send_msg(mod)
                          self.logger.info("Delete the flow entries in Edge switches number %d which match port: %d and src: %d", item[0], item[3],item[1])
                          #break
                  self.Slow_attack = None
                  self.A.clear()
        """
        if stat == ev.msg.body[-1]:
            self.tcpcounter+=1
            if self.tcpcounter >= len(self.Edgeswitch):
                   self.Threshold_tcp = (self.Threshold_tcp * 0.95) + (self.Gratest_tcp * 0.05)
                   print "self.Threshold_tcp", round(self.Threshold_tcp *2) + 15 , self.tcpcounter, self.Gratest_tcp   
                   self.Gratest_tcp = 3
                   file = open ('x.txt', 'a')
                   file.write(str(self.Threshold_tcp))
                   file.close
                   self.tcpcounter = 0

      """
      if self.Slow_attack != None: 
         time.sleep(1)
         cookie = cookie_mask = 0
         match = ofp_parser.OFPMatch(eth_dst= self.Slow_attack)
         table_id=1
         req = ofp_parser.OFPFlowStatsRequest(datapath, 0,ofp.OFPTT_ALL,ofp.OFPP_ANY, ofp.OFPG_ANY,cookie, cookie_mask,match, table_id)
         datapath.send_msg(req)
      """
 
              
    def Diffie_Hellman(self, src):
        
        #G = 15
        p = 21841
        a = randint(0,10000)
        Public_Key = 15**a % 21841
        self.Key[src] = (int(Public_Key), 0, a, 0)# sending Msg to src with a public Key
        Keyfile = open ('Key.txt', 'w')
        Keyfile.write(str(self.Key))
        Keyfile.close
        
class ThreadingExample(SimpleSwitch13):
    """ Threading example class
    The run() method will be started and it will run in the background
    until the application exits.
    """

    def __init__(self):
        """ Constructor
        """
        thread1 = threading.Thread(target=self.foo, args=())
        thread1.daemon = True                            # Daemonize thread
        thread1.start()

        thread2 = threading.Thread(target=self.Monitor, args=())
        thread2.daemon = True                            # Daemonize thread
        thread2.start()

        thread3 = threading.Thread(target=self.get_CpuMemory_usage, args=())
        thread3.daemon = True                            # Daemonize thread
        thread3.start()

    def Monitor(self):
       time.sleep(30)
       while True:
          time.sleep(3)
          self.send_port_stats_request()
          if len(self.newlocation) > 0:
            for item in self.newlocation:
               self.send_flow_stats_request(item)
          else:
            for dpid in self.Edgeswitch:#SNY_Attack
               datapath = self.Data_Path[dpid]
               ofp = datapath.ofproto
               ofp_parser = datapath.ofproto_parser

               cookie = cookie_mask = 0
               match = ofp_parser.OFPMatch()
               table_id=0
               req = ofp_parser.OFPFlowStatsRequest(datapath, 0,ofp.OFPTT_ALL,ofp.OFPP_ANY, ofp.OFPG_ANY,cookie, cookie_mask,match, table_id)
               datapath.send_msg(req)
          
    def get_CpuMemory_usage(self):
        point = 0
        while True:
          pid = os.getpid()
          #print(pid)
          ps = psutil.Process(pid)
          cpuUse = ps.cpu_percent(interval=1)
          memoryUse = ps.memory_percent()
          point = point + 1
          self.CPU.append(cpuUse)
          self.Memory.append(memoryUse)
          Cpufile = open ('CpuUsage.txt', 'w')
          Cpufile.write(str(self.CPU))
          Cpufile.close
          Memoryfile = open ('memoryUsage.txt', 'w')
          Memoryfile.write(str(self.Memory))
          Memoryfile.close
          Entryfile = open ('Flowcounter.txt', 'w')
          Entryfile.write(str(self.Flowcounter))
          Entryfile.close
          
          t_end = time.time() + 3 
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
                  dpid = rdata[0]
                  src = rdata[1]
                  dst = rdata[2]
                  in_port = rdata[3]#MacAddress
                  ip_src = rdata[4]
                  buffer_id = rdata[5]
                  msg_data = rdata[6]

                  datapath = self.Data_Path[dpid]
                  pkt = packet.Packet(msg_data)
                  pkt_tcp = pkt.get_protocol(tcp.tcp)

                  if len(rdata) < 8:
                    self.mac_to_port[dpid][src] = in_port
                    self.Hostinfo.append((dpid, src, ip_src, in_port))
                    #pass # to Install an entry                 
                  elif rdata[7] == True:
                    self.Diffie_Hellman(src) 
                    self.newlocation.append((dpid, src, ip_src, in_port))
                    time.sleep(1)
                  else:
                    print rdata[7]
                    print "BLOCK %s %s %s %s" %(dpid, src, dst, in_port)
                    actions =[]
                    match = parser.OFPMatch(in_port=in_port)
                    self.add_flow(datapath, 5, match, actions, table_id = 1)
                    return
                  Private_key = 0
                  if src in self.Key.keys():                 
                    if self.Key[src][1] != 0:
                        self.Key[src][3] = self.Key[src][1]**self.Key[src][2]% 21841
                        Keyfile = open ('Key.txt', 'w')
                        Keyfile.write(str(self.Key))
                        Keyfile.close

                  if dst in self.mac_to_port[dpid]:
                     out_port = self.mac_to_port[dpid][dst]
                  else:
                    out_port = ofproto.OFPP_FLOOD

                  actions = [parser.OFPActionOutput(out_port)]

                  # install a flow to avoid packet_in next time
                  if out_port != ofproto.OFPP_FLOOD:
                    if Private_key:
                         match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src, eth_type=0x8847,mpls_label=Private_key)
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
