#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Controller, OVSKernelSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
from random import randint
import time, datetime
import os, psutil
import threading
from mininet.topo import Topo

Pkt_number = 0
FPkt_number = 0
def emptyNet():
   os.system('sudo mn -c')
   HostNumber = 12
   net = Mininet(controller=RemoteController,  switch=OVSKernelSwitch)
   c1 = net.addController('c1', controller=RemoteController, ip="127.0.0.1")
   c2 = net.addController('c2', controller=RemoteController, ip="127.0.0.2")
   host= [0]*HostNumber 
   for i in range(1,HostNumber+1):
      if i < 10 :
           mac = '00:00:00:00:00:0%s'%str(i)
           ip = '10.0.0.%s'%str(i)
           host[i-1]= net.addHost('h%s'%str(i),  ip=ip, mac=mac)
      elif i < 100:      
           mac = '00:00:00:00:00:%s'%str(i)
           ip = '10.0.0.%s'%str(i)
           host[i-1]= net.addHost('h%s'%str(i),  ip=ip, mac=mac)
      else:
           x = i
           i = i - 100
           if i < 10:
             i = "0" + str(i)
           mac = '00:00:00:00:01:%s'%str(i)
           ip = '10.0.0.1%s'%str(i)
           host[x-1]= net.addHost('h%s'%str(x),  ip=ip, mac=mac)
   
   server = [0]*1
   server[0] = net.addHost('server', ip='10.0.0.199', mac='00:00:00:00:01:99')
   print server
   #time.sleep(10)
   switch = [0]*11 
   for i in range(1,12):
      # x = i + 1
      if i < 10 :
          dpid='000000000000010%s'%str(i)
      else:      
          dpid='00000000000001%s'%str(i)     
      switch[i-1]= net.addSwitch('s%s'%str(i), dpid= dpid)
   linkopts = dict(cls=TCLink, bw=1000, delay='5ms')#1Gb
   ingresslinks = dict(cls=TCLink, bw=100, delay='5ms')#800Mb = 100MByte
   print 'bulding links for edge switches from S1 to S4.'
   net.addLink(switch[0], switch[4], **linkopts)
   net.addLink(switch[1], switch[5], **linkopts)
   net.addLink(switch[2], switch[6], **linkopts)
   net.addLink(switch[3], switch[7], **linkopts)

   net.addLink(switch[4], switch[5], **linkopts)
   net.addLink(switch[4], switch[8], **linkopts)
   net.addLink(switch[4], switch[10], **linkopts)
   net.addLink(switch[5], switch[6], **linkopts)
   net.addLink(switch[6], switch[7], **linkopts)

   net.addLink(switch[7], switch[8], **linkopts)
   net.addLink(switch[7], switch[10], **linkopts)

   net.addLink(switch[8], switch[9], **linkopts)
   net.addLink(switch[9], switch[10], **linkopts)
   


   print 'bulding links between hosts and edge switches.'
   for i in range(0,4):
      if i == 0:
         for x in range(0,3):
               net.addLink(switch[i], host[x], **ingresslinks)
      elif i == 1:
         for x in range(3,6):
               net.addLink(switch[i], host[x], **ingresslinks)
      elif i == 2:
         for x in range(6,9):
               net.addLink(switch[i], host[x], **ingresslinks)
      elif i == 3:
         for x in range(9,12):
               net.addLink(switch[i], host[x], **ingresslinks)
      else:
          pass     
   net.addLink(switch[10], server[0], **linkopts)
                         

   
   net.build()
   c1.start()
   c2.start()
   #c1.cmd("tcpdump -i any -nn port 6633 -U -w mylog &")
   
   for i in range(0,11):
     if i < 4:
      switch[i].start([c1,c2])
     else:
      switch[i].start([c1])
   #net.start()
   enableSTP()
   net.staticArp()
   
   info( '\n*** Starting web server ***\n')
   server = net.get('server')
   #os.system('sudo tcpdump -i lo -w ryu-local.cap &')
   os.system('sudo tcpdump -i any tcp -w TCP.pcap &')
   server.cmdPrint('python -m SimpleHTTPServer 80 &')
   server.cmd('sudo tcpdump -i server-eth0 port 80 -w server.pcap &')
   info( '*** Starting the simulation in 10 Seconds ***\n')
   info( '*** Run the ryu Controller now ***\n')

   time.sleep(30)
   net.pingAll()
   #for i in range(1,HostNumber +1):
     #client=net.get('h%s'%str(i))
     #client.cmdPrint('sudo ping -c 1 10.0.0.199')
   
   t_end = time.time() + 1 
   while time.time() < t_end:
      pass

   finish_time = 0
   start_time = time.time()
   while finish_time < 63:# Training time to gather the information       
     for i in range(1,HostNumber +1):
       t = threading.Thread(target= Training, args=(net,i,HostNumber,))
       t.setDaemon(True)
       t.start()

     t_end = time.time() + 5 
     while time.time() < t_end:
             pass     
     finish_time = time.time() - start_time

   global Pkt_number
   global FPkt_number

   while finish_time <203:# testing time to gather the information  
     for i in range(1,HostNumber +1):
       t = threading.Thread(target= Attack, args=(net,i,HostNumber,))
       t.setDaemon(True)
       t.start()
     print "Attack"
     time.sleep(1)          
     finish_time = time.time() - start_time

   print 'finish_time = ', finish_time 
   print "\nthe benign packt number", Pkt_number
   print "\n the malicious packt number", FPkt_number
   
   CLI( net )
   net.stop()
       
   
def Training(net,i, HostNumber):
      #dst = Mac(randint(1,HostNumber + 1)) use this for udp experiment
      dst = '00:00:00:00:01:99'# for TCP experiment
      src = Mac(i) 
      Pktnumber = randint(1,5)# in TCP, this line acts number of the requestes 
      #x = randint(1,HostNumber + 1)
      client=net.get('h%s'%str(i))
      client.cmdPrint('python /home/abdullah/ryu/ryu/app/TCPNormal.py %s %s %d &' %(src,dst,Pktnumber))         
 

def Attack(net,i, HostNumber):
      global Pkt_number
      global FPkt_number
      #dst = Mac(randint(1,HostNumber + 1))
      dst = '00:00:00:00:01:99'# for TCP experiment
      src = Mac(i)             
      if i == 11:
               client=net.get('h%s'%str(i))
               client.cmdPrint('hping3 10.0.0.199 -S -c 20 -i u1 --verbose -s 2235 -p 80 ')#--data 500
               FPkt_number = FPkt_number + 150

               Pktnumber = randint(1,2) 
               client=net.get('h%s'%str(i))
               client.cmd('python /home/abdullah/ryu/ryu/app/TCPNormal.py %s %s %d &' %(src,dst,Pktnumber))
               Pkt_number = Pkt_number + Pktnumber        
      else:
           Pktnumber = randint(1,2)            
           client=net.get('h%s'%str(i))
           client.cmd('python /home/abdullah/ryu/ryu/app/TCPNormal.py %s %s %d &' %(src,dst,Pktnumber))
           Pkt_number = Pkt_number + Pktnumber 
 
def Mac(i):
    if i < 10 :
       mac = '00:00:00:00:00:0%s'%str(i)
    elif i < 100:      
       mac = '00:00:00:00:00:%s'%str(i)
    else:
           x = i
           i = i - 100
           if i < 10:
             i = "0" + str(i)
           mac = '00:00:00:00:01:%s'%str(i)
    return mac

def enableSTP():
    """
    //HATE: Dirty Code
    """
    for x in range(1,12):
        cmd = "ovs-vsctl set Bridge s%s stp_enable=true" %x
        os.system(cmd)
        print cmd    

if __name__ == '__main__':

    setLogLevel( 'info' )
    emptyNet()
