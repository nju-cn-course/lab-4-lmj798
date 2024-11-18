#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
from switchyard.lib.userlib import *
import switchyard

def insert_by_max(l: list, a):
    if len(l) == 0:
        l.append(a)
    else:
        c = 0
        for i in l:
            p1 = i[0].prefixlen
            p2 = a[0].prefixlen
            if p1 >= p2:
                c += 1
            else:
                break
        l.insert(c, a)

class Waiting_packet:
    def __init__(self, pkt, intf, dstip):
        self.packet = pkt
        self.last_send_time = 0
        self.count = 0
        self.router_intf = intf
        self.next_hop_ip = dstip



class Router(object):
    def __init__(self, net):
        self.net = net
        self.my_arptable = {}
        self.count_of_print = 0
        self.forwarding_table = []
        self.waiting_queue = []
        
        for intf in self.net.interfaces():
            ipad = IPv4Address(int(intf.ipaddr) & int(intf.netmask))
            x = IPv4Network(str(ipad)+'/'+str(intf.netmask))
            x1 = [x, '', intf.name]
            insert_by_max(self.forwarding_table, x1)
        with open("forwarding_table.txt", "r") as flies:
            a = flies.readlines()
        for i in range(len(a)):
            a[i] = a[i].split(" ")
            if i != len(a)-1:
                a[i][3] = a[i][3].strip("\n")
        for i in a:
            x2 = [IPv4Network(i[0]+'/'+i[1]), i[2], i[3]]
            insert_by_max(self.forwarding_table, x2)

    def send_arp_request(self, router_intf, next_hop_ip):
        ether = Ethernet()
        ether.src = router_intf.ethaddr
        ether.dst = 'ff:ff:ff:ff:ff:ff'
        ether.ethertype = EtherType.ARP
        arp = Arp(operation=ArpOperation.Request,
                  senderhwaddr=router_intf.ethaddr,
                  senderprotoaddr=router_intf.ipaddr,
                  targethwaddr='ff:ff:ff:ff:ff:ff',
                  targetprotoaddr=next_hop_ip)
        arppacket = ether + arp
        self.net.send_packet(router_intf.name, arppacket)

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        arp = packet.get_header(Arp)
        ipv4 = packet.get_header(IPv4)
        if arp:
            self.my_arptable[arp.senderprotoaddr] = [arp.senderhwaddr, time.time()]
            if arp.operation == ArpOperation.Request:
                for intf in self.net.interfaces():
                    if intf.ipaddr == arp.targetprotoaddr:
                        response = create_ip_arp_reply(intf.ethaddr, arp.senderhwaddr, intf.ipaddr, arp.senderprotoaddr)
                        self.net.send_packet(ifaceName, response)
            for i in list(self.my_arptable.keys()):
                if time.time()-self.my_arptable[i][1] >= 100:
                    del self.my_arptable[i]
            log_info(str(self.count_of_print))
            self.count_of_print += 1
            log_info(str(self.my_arptable))
        elif ipv4:
            ipv4.ttl -= 1
            judging = True
            interface_macs = [intf.ethaddr for intf in self.net.interfaces()]
            ether = packet.get_header(Ethernet)
            if ether.dst != 'ff:ff:ff:ff:ff:ff' and ether.dst not in interface_macs:
                judging = False
            for intf in self.net.interfaces():
                if ipv4.dst == intf.ipaddr:
                    judging = False
                    break
            if judging:
                fw_index = -1
                for i in range(len(self.forwarding_table)):
                    if ipv4.dst in self.forwarding_table[i][0]:
                        fw_index = i
                        break
                if fw_index != -1:
                    if self.forwarding_table[fw_index][1]:
                        next_hop_ip = IPv4Address(self.forwarding_table[fw_index][1])
                    else:
                        next_hop_ip = ipv4.dst
                    for intf in self.net.interfaces():
                        if intf.name == self.forwarding_table[fw_index][2]:
                            router_intf = intf
                            break
                    packet[0].src = router_intf.ethaddr
                    self.waiting_queue.append(Waiting_packet(packet, router_intf, next_hop_ip))




        
    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            bb = True
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                bb = False
            except Shutdown:
                break
            if bb:
                self.handle_packet(recv)
            re = []
            without_query = []
            for i in self.waiting_queue:
                if i.next_hop_ip in self.my_arptable.keys():
                    mac = self.my_arptable[i.next_hop_ip][0]
                    i.packet[0].dst = str(mac)
                    self.net.send_packet(i.router_intf.name, i.packet)
                    without_query.append(i)
                elif time.time()-i.last_send_time>=1 and i.next_hop_ip not in re:
                    if i.count<5:
                        re.append(i.next_hop_ip)
                        self.send_arp_request(i.router_intf, i.next_hop_ip)
                        i.count += 1
                        i.last_send_time = time.time()
                    else:
                        nip = i.next_hop_ip
                        for j in self.waiting_queue:
                            if j.next_hop_ip == nip:
                                without_query.append(j)
            for i in without_query:
                self.waiting_queue.remove(i)

        self.stop()

    def stop(self):
        self.net.shutdown()


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()