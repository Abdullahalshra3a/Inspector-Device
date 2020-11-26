from scapy.all import *
import sys, os
from scapy.contrib.mpls import *    

def generatePackets():
    if len(sys.argv) != 4:
        print "Usage: arping2tex <net>\n eg: arping2text 192.168.1.0/24"
        sys.exit(1)
    src= sys.argv[1]
    dst= sys.argv[2]
    x = int(sys.argv[3])#Packt number
    data=RandString(size=4)#54 byte      
    increment_sequence=len(data)
    ethr = Ether(src= src, dst= dst)
    ip=IP()        
    pkt = (ethr/ip/UDP(sport = 2540, dport=5080)/data)
    if Ether().src in Key.keys():
      if Key[Ether().src][3] !=0:
             mpls_lables=MPLS(label=int(Key[Ether().src][3]))
             pkt = (ethr/mpls_lables/ip/UDP(sport = 2540, dport=2580)/data)
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
             pkt = (ethr/mpls_lables/ip/UDP(sport = 2540, dport=2580)/data)
       else:
             pass

    sendp(pkt, count = x)


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
            
