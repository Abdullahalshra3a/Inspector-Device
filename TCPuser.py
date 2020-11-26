from scapy.all import *
import sys, os, ast, time
from random import randint
from scapy.contrib.mpls import *    


def generatePackets():
    if len(sys.argv) != 4:
        print "Usage: arping2tex <net>\n eg: arping2text 192.168.1.0/24"
        sys.exit(1)
    src= sys.argv[1]
    dst= sys.argv[2]
    x = int(sys.argv[3])#request number (1 - 5)
    
    #os.system("iptables -A OUTPUT  -p tcp --sport 80 --tcp-flags RST RST -j DROP")# to stop RST Flages from the local host system
    data=RandString(size=504)#54 byte 

    increment_sequence=len(data)
    ethr = Ether(src= src, dst= dst)
    ip=IP(src= get_if_addr(conf.iface), dst = '10.0.0.3')
    withMPLS = False
    Key = read_data()
    for req in range(1, x+1):
       sport = randint(50,65500)     
       os.system("iptables -A OUTPUT  -p tcp --sport %d --tcp-flags RST RST -j DROP"%sport)# to stop RST Flages from the local host system
       # three way handshake and sending packets   
       #data to be sent in each packet        
       pkt = (ethr/ip/TCP(sport = sport, dport=80,flags='S', seq=0))
       if Ether().src in Key.keys():
          if Key[Ether().src][3] !=0:
             mpls_lables=MPLS(label=int(Key[Ether().src][3]))
             pkt = (ethr/mpls_lables/ip/TCP(sport = sport, dport=80,flags='S', seq=0))
             withMPLS = True
          elif Key[Ether().src][0] != 0:
             a = randint(0,10000)
             t = Key[Ether().src]
             lst = list(t)
             lst[1] = int(15**a % 21841)# sending Msg to controller with a public Key
             lst [3] = int(Key[Ether().src][0]**a % 21841)
             t = tuple(lst)
             Key[Ether().src] = t
             write_data(Key)
             mpls_lables=MPLS(label=Key[Ether().src][3], s=0, ttl=255)
             pkt = (ethr/mpls_lables/ip/TCP(sport = sport, dport=80,flags='S', seq=0))
             withMPLS = True
          else:
             pass

       SYNACK=srp1(pkt,timeout = 0.2)
       if SYNACK:
          i = randint(2,10)
          sequence=SYNACK.ack
          ackno=SYNACK.seq+1
          for q in range(1,i+1):
             if withMPLS:
                pkt = (ethr/ip/mpls_lables/TCP(sport = sport, dport=80, flags="A", seq=sequence, ack = ackno)/Raw(data))
             else:
                pkt = (ethr/ip/TCP(sport = sport, dport=80, flags="A", seq=sequence, ack=ackno)/Raw(data))

             if q == i:
                Response = srp1(pkt)
                sequence+= increment_sequence
                ackno=Response.seq          
             else:
                sendp(pkt) 
                sequence+= increment_sequence
       else:
          continue

       #close connection (ports)
       out = True
       while out:
         if withMPLS:
            FIN = srp1(ethr/mpls_lables/ip/TCP(sport = sport, dport=80, flags="FPA", seq=sequence, ack = ackno))  
         else:
            FIN = srp1(ethr/ip/TCP(sport = sport, dport=80, flags="FPA", seq=sequence, ack = ackno))
         if FIN.sprintf('%TCP.flags%') == 'F' or FIN.sprintf('%TCP.flags%') == 'FA' :
            out = False
            ackno=Response.seq + 1           

       sendp(ethr/ip/TCP(sport = sport, dport=80,flags='A',seq= FIN.ack, ack = ackno))                



def read_data():
      file = open("/home/abdullah/ryu/Key.txt", "r")
      contents = file.read()
      dictionary = ast.literal_eval(contents)
      file.close()
      return dictionary

def write_data(Key):
        Keyfile = open ('/home/abdullah/ryu/Key.txt', 'w')
        Keyfile.write(str(Key))
        Keyfile.close 
   
if __name__ == '__main__':
    generatePackets()
            
