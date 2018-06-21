#!/usr/bin/python

from __future__ import print_function
from __future__ import print_function
from scapy.all import *
import scapy.contrib.igmp
import scapy.contrib.igmpv3
import argparse

group_ip = "224.10.10.10"
interface = "enp4s0"
vorbose = 0

parser=argparse.ArgumentParser(prog='igmp_query_responder.py',add_help=True)
parser.add_argument('-g', '--group_addr',action='store')
parser.add_argument('-i', '--interface',action='store')
parser.add_argument('-v', '--vorbose',action='store')
args = parser.parse_args()
if args.group_addr:
    group_ip=args.group_addr

if args.interface:
    interface=args.interface
if args.vorbose:
    vorbose=1

def print_packet(packet):
    ip_layer = packet.getlayer(IP)
    print("[!] New Packet: {src} -> {dst}".format(src=ip_layer.src, dst=ip_layer.dst))

igmp_query_maddr="224.0.0.1"

frame_igmp_report = IP(dst=group_ip)/scapy.contrib.igmpv3.IGMP(type=0x16,gaddr=group_ip)
frame_igmp_join = IP(dst=group_ip)/scapy.contrib.igmpv3.IGMP(type=0x22,gaddr=group_ip)

def igmp_report(packet):
    print("[%s]igmp query received from %s" % (group_ip, str(packet.getlayer(IP).src)))
    if(vorbose):
        packet.show()
    send(frame_igmp_report,iface=interface,verbose=0)
    print("----->[%s]igmp membership report sent." % group_ip)

'''main code starts from here'''
send(frame_igmp_join,iface=interface,verbose=0)
print( "subscribing %s on %s" % (group_ip,interface))

while(1):
    sniff(iface=interface,filter="igmp",prn=igmp_report,count=1)
