from scapy.all import *
from scapy.utils import rdpcap


if len(sys.argv) != 3:
        print "Usage: argument numbers have to be 3"
        sys.exit(1)
for i in range(22):
  pkts=rdpcap("%d.pcap", i)  # could be used like this rdpcap("filename",500) fetches first 500 pkts
  for pkt in pkts:
     pkt[Ether].src= sys.argv[1]  # i.e new_src_mac="00:11:22:33:44:55"
     pkt[Ether].dst= sys.argv[2]
     pkt[IP].src= get_if_addr(conf.iface) # i.e new_src_ip="255.255.255.255"
     pkt[IP].dst= "10.0.0.199"
     pkt[Tcp].dport=target_port
     sendp(pkt)
