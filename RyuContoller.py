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

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    Hostnumber = 123
    Hostinfo ={}
    Data_Path = {}
    Flowcounter = {}
    Edgeswitch = [257,258,259,260]
    mac_to_port = {}
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
          if src in self.Hostinfo.keys():
              self.logger.info("the user in Database %s %s %s %s", dpid, src, dst, in_port)
              pass
          else:
             print "unuthucated user"
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
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 100, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 100, match, actions)
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
                  print 'the pakt is:', rdata
                  #c.send('Thank you for connecting')
                  ip_src = rdata[0]
                  in_port = rdata[1]
                  dpid = rdata[2]
                  src = rdata[3]
                  dst = rdata[4]
                  buffer_id = rdata[5]
                  msg_data = rdata[6]
                  datapath = self.Data_Path[dpid]
                  if src in self.Hostinfo.keys():
                      pass
                  elif len(self.Hostinfo) >= self.Hostnumber :
                      print "BLOCK"
                      self.logger.info("packet in Socket %s %s %s %s", dpid, src, dst, in_port)
                      actions = []
                      match = parser.OFPMatch(in_port=in_port)
                      self.add_flow(datapath, 100, match, in_port , actions)#should be 1000
                      return
                  else:
                      print "new item"
                      self.Hostinfo[src] = (ip_src,in_port,dpid)
                  
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
                    # flow_mod & packet_out
                    if buffer_id != ofproto.OFP_NO_BUFFER:
                      self.add_flow(datapath, 100, match, actions, buffer_id)
                      return
                    else:
                      self.add_flow(datapath, 100, match, actions)
                  data = None
                  if buffer_id == ofproto.OFP_NO_BUFFER:
                     data = msg_data

                  out = parser.OFPPacketOut(datapath=datapath, buffer_id=buffer_id,
                                  in_port=in_port, actions=actions, data=data)
                  datapath.send_msg(out)    
example = ThreadingExample()                
