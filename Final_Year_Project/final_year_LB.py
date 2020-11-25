# coding=utf-8
# !/usr/bin/python3

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import ether_types
from ryu.lib.packet import udp
from ryu.lib.packet import tcp
from ryu.lib import mac, ip
from ryu.lib import hub
from ryu.ofproto import inet
from ryu.topology.api import get_switch, get_link, get_host
from ryu.app.wsgi import ControllerBase
from ryu.topology import event, switches

from collections import defaultdict
from operator import itemgetter
from dataclasses import dataclass
import heapq

import threading
import os
import random
import time

# Cisco Reference bandwidth = 1 Gbps
# Cisco Dijkstra values:
REFERENCE_BW = 10000000

DEFAULT_BW = 10000000

MAX_PATHS = 1


@dataclass
class Paths:
    """ Paths container"""
    path: []
    cost: float


class ProjectController13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ProjectController13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapath_list = {}  # SwitchDPID dictionary: SwitchDP
        self.arp_table = {}  # MAC:PORT mapping
        self.switches = []  # List of switches
        self.hosts = {}  # The dictionary that stores data in EthernetSource format:(DPID_of_switch, In_Port)
        # In the variable below, we store the dictionary in which the values of the Sets are stored in order to avoid a repetition!
        self.neighbor = defaultdict(
            dict)  # Neighbors, the structure is this: {SwithId: {Neighbour1:Port_Switcha,Neighbour2:Port_Switcha}}
        self.bandwidth = defaultdict(lambda: defaultdict(
            lambda: DEFAULT_BW))  # Structure the same as before, calling for two values only this time [switch][port]
        self.prev_bytes = defaultdict(lambda: defaultdict(
            lambda: 0))  # Structure the same as before, calling for two values only this time [switch][port]
        self.path_table = {}  # Current path structure (src, in_port, dst, out_port):Path
        self.paths_table = {}  # Possible pathways structure (src, in_port, dst, out_port):Paths
        self.path_with_ports_table = {}  # Current (optimal) path with ports structure (src, in_port, dst, out_port):Path_with_ports
        self.path_calculation_keeper = []  # A list containing a tuple (src, in_port, dst, out_port)

    def get_paths_and_costs(self, src, dst):
        """
        Implementation of Breadth-First Search Algorithm (BFS)
        Output of this function returns a list of class Paths objects
        """
        if src == dst:
            # host target is on the same switch
            # print("Source is the same as destination!")
            return [Paths(src, 0)]

        queue = [(src, [src])]
        paths = list()  # If we use a generator make a comment.
        while queue:
            (edge, path) = queue.pop()
            for vertex in set(self.neighbor[edge]) - set(path):
                if vertex == dst:
                    path_to_dst = path + [vertex]
                    cost_of_path = self.get_path_cost(path_to_dst)
                    paths.append(Paths(path_to_dst, cost_of_path))
                else:
                    queue.append((vertex, path + [vertex]))
        return paths  # Comment out if using a generator.

    def get_path_cost(self, path):
        """ arg path is a list with all nodes in our route """
        path_cost = []
        for i in range(len(path) - 1):
            port1 = self.neighbor[path[i]][path[i + 1]]
            # port2 = self.neighbor[path[i + 1]][path[i]]
            bandwidth_between_two_nodes = self.bandwidth[path[i]][port1]
            # path_cost.append(REFERENCE_BW / bandwidth_between_two_nodes)
            path_cost.append(bandwidth_between_two_nodes)
        return sum(path_cost)

    def get_n_optimal_paths(self, paths, number_of_optimal_paths=MAX_PATHS):
        """arg Paths is a list containing lists of possible paths"""
        costs = [path.cost for path in paths]
        optimal_paths_indexes = list(map(costs.index, heapq.nsmallest(number_of_optimal_paths, costs)))
        optimal_paths = [paths[op_index] for op_index in optimal_paths_indexes]
        return optimal_paths

    def add_ports_to_paths(self, paths, first_port, last_port):
        """
        Add the ports to all switches including hosts
        """
        paths_n_ports = []
        bar = {}  # Dictionary with switchDPID structure: (Ingress_Port, Egress_Port)
        in_port = first_port
        for s1, s2 in zip(paths[0].path[:-1], paths[0].path[1:]):
            out_port = self.neighbor[s1][s2]
            bar[s1] = (in_port, out_port)
            in_port = self.neighbor[s2][s1]
        bar[paths[0].path[-1]] = (in_port, last_port)
        paths_n_ports.append(bar)
        return paths_n_ports

    def install_paths(self, src, first_port, dst, last_port, ip_src, ip_dst, type, pkt):
        """ Pathway installation """
        # self.topology_discover(src, first_port, dst, last_port)

        if (src, first_port, dst, last_port) not in self.path_calculation_keeper:
            self.path_calculation_keeper.append((src, first_port, dst, last_port))
            self.topology_discover(src, first_port, dst, last_port)
            self.topology_discover(dst, last_port, src, first_port)

        for node in self.path_table[(src, first_port, dst, last_port)][0].path:

            dp = self.datapath_list[node]
            ofp = dp.ofproto
            ofp_parser = dp.ofproto_parser

            actions = []

            in_port = self.path_with_ports_table[(src, first_port, dst, last_port)][0][node][0]
            out_port = self.path_with_ports_table[(src, first_port, dst, last_port)][0][node][1]

            actions = [ofp_parser.OFPActionOutput(out_port)]

            if type == 'UDP':
                nw = pkt.get_protocol(ipv4.ipv4)
                l4 = pkt.get_protocol(udp.udp)

                match = ofp_parser.OFPMatch(in_port=in_port,
                                            eth_type=ether_types.ETH_TYPE_IP,
                                            ipv4_src=ip_src,
                                            ipv4_dst=ip_dst,
                                            ip_proto=inet.IPPROTO_UDP,
                                            udp_src=l4.src_port,
                                            udp_dst=l4.dst_port)

                self.logger.info(f"Installed path in switch: {node} out port: {out_port} in port: {in_port} ")

                self.add_flow(dp, 33333, match, actions, 10)
                self.logger.info("UDP Flow added ! ")

            elif type == 'TCP':

                nw = pkt.get_protocol(ipv4.ipv4)
                l4 = pkt.get_protocol(tcp.tcp)

                match = ofp_parser.OFPMatch(in_port=in_port,
                                            eth_type=ether_types.ETH_TYPE_IP,
                                            ipv4_src=ip_src,
                                            ipv4_dst=ip_dst,
                                            ip_proto=inet.IPPROTO_TCP,
                                            tcp_src=l4.src_port,
                                            tcp_dst=l4.dst_port)

                self.logger.info(f"Installed path in switch: {node} out port: {out_port} in port: {in_port} ")

                self.add_flow(dp, 44444, match, actions, 10)
                self.logger.info("TCP Flow added ! ")

            elif type == 'ICMP':

                nw = pkt.get_protocol(ipv4.ipv4)

                match = ofp_parser.OFPMatch(in_port=in_port,
                                            eth_type=ether_types.ETH_TYPE_IP,
                                            ipv4_src=ip_src,
                                            ipv4_dst=ip_dst,
                                            ip_proto=inet.IPPROTO_ICMP)

                self.logger.info(f"Installed path in switch: {node} out port: {out_port} in port: {in_port} ")

                self.add_flow(dp, 22222, match, actions, 10)
                self.logger.info("ICMP Flow added ! ")

            elif type == 'ARP':
                match_arp = ofp_parser.OFPMatch(in_port=in_port,
                                                eth_type=ether_types.ETH_TYPE_ARP,
                                                arp_spa=ip_src,
                                                arp_tpa=ip_dst)

                self.logger.info(f"Install path in switch: {node} out port: {out_port} in port: {in_port} ")

                self.add_flow(dp, 1, match_arp, actions, 10)
                self.logger.info("ARP Flow added ! ")

        # return self.path_with_ports_table[0][src][1]
        return self.path_with_ports_table[(src, first_port, dst, last_port)][0][src][1]

    def add_flow(self, datapath, priority, match, actions, idle_timeout, buffer_id=None):
        """ Method Provided by the source Ryu library. """

        ofproto = datapath.ofproto  # Library definition for use of OpenFlow versions
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match, idle_timeout=idle_timeout,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, idle_timeout=idle_timeout, instructions=inst)
        datapath.send_msg(mod)

    def run_check(self, ofp_parser, dp):
        """ Every second the thread polls the switches about the port status and the PortStatsReq is sent"""
        threading.Timer(1.0, self.run_check, args=(ofp_parser, dp)).start()

        req = ofp_parser.OFPPortStatsRequest(dp)
        # self.logger.info(f"Port Stats Request has been sent for sw: {dp} !")
        dp.send_msg(req)

    def topology_discover(self, src, first_port, dst, last_port):
        """ Calculation of the optimal path for the set parameters + port assignment """
        threading.Timer(1.0, self.topology_discover, args=(src, first_port, dst, last_port)).start()
        paths = self.get_paths_and_costs(src, dst)
        path = self.get_n_optimal_paths(paths)
        path_with_port = self.add_ports_to_paths(path, first_port, last_port)

        self.logger.info(f"Possible paths: {paths}")
        self.logger.info(f"Optimal Path with port: {path_with_port}")

        self.paths_table[(src, first_port, dst, last_port)] = paths
        self.path_table[(src, first_port, dst, last_port)] = path
        self.path_with_ports_table[(src, first_port, dst, last_port)] = path_with_port

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes", ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        if src not in self.hosts:
            self.hosts[src] = (dpid, in_port)

        out_port = ofproto.OFPP_FLOOD

        if eth.ethertype == ether_types.ETH_TYPE_IP:
            nw = pkt.get_protocol(ipv4.ipv4)
            if nw.proto == inet.IPPROTO_UDP:
                l4 = pkt.get_protocol(udp.udp)
            elif nw.proto == inet.IPPROTO_TCP:
                l4 = pkt.get_protocol(tcp.tcp)

        if eth.ethertype == ether_types.ETH_TYPE_IP and nw.proto == inet.IPPROTO_UDP:
            src_ip = nw.src
            dst_ip = nw.dst

            self.arp_table[src_ip] = src
            h1 = self.hosts[src]
            h2 = self.hosts[dst]

            self.logger.info(f" IP Proto UDP from: {nw.src} to: {nw.dst}")

            out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip, 'UDP', pkt)
            self.install_paths(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip, 'UDP', pkt)

        elif eth.ethertype == ether_types.ETH_TYPE_IP and nw.proto == inet.IPPROTO_TCP:
            src_ip = nw.src
            dst_ip = nw.dst

            self.arp_table[src_ip] = src
            h1 = self.hosts[src]
            h2 = self.hosts[dst]

            self.logger.info(f" IP Proto TCP from: {nw.src} to: {nw.dst}")

            out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip, 'TCP', pkt)
            self.install_paths(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip, 'TCP', pkt)

        elif eth.ethertype == ether_types.ETH_TYPE_IP and nw.proto == inet.IPPROTO_ICMP:
            src_ip = nw.src
            dst_ip = nw.dst

            self.arp_table[src_ip] = src
            h1 = self.hosts[src]
            h2 = self.hosts[dst]

            self.logger.info(f" IP Proto ICMP from: {nw.src} to: {nw.dst}")

            out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip, 'ICMP', pkt)
            self.install_paths(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip, 'ICMP', pkt)

        elif eth.ethertype == ether_types.ETH_TYPE_ARP:
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip

            if arp_pkt.opcode == arp.ARP_REPLY:
                self.arp_table[src_ip] = src
                h1 = self.hosts[src]
                h2 = self.hosts[dst]

                self.logger.info(f" ARP Reply from: {src_ip} to: {dst_ip} H1: {h1} H2: {h2}")

                out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip, 'ARP', pkt)
                self.install_paths(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip, 'ARP', pkt)

            elif arp_pkt.opcode == arp.ARP_REQUEST:
                if dst_ip in self.arp_table:
                    self.arp_table[src_ip] = src
                    dst_mac = self.arp_table[dst_ip]
                    h1 = self.hosts[src]
                    h2 = self.hosts[dst_mac]

                    self.logger.info(f" ARP Reply from: {src_ip} to: {dst_ip} H1: {h1} H2: {h2}")

                    out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip, 'ARP', pkt)
                    self.install_paths(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip, 'ARP', pkt)

        actions = [parser.OFPActionOutput(out_port)]

        data = None

        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        """
        To send packets for which we dont have right information to the controller
        Method Provided by the source Ryu library.
        """

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions, 10)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        """Reply to the OFPPortStatsRequest, visible beneath"""
        switch_dpid = ev.msg.datapath.id
        for p in ev.msg.body:
            self.bandwidth[switch_dpid][p.port_no] = (p.tx_bytes - self.prev_bytes[switch_dpid][
                p.port_no]) * 8.0 / 1000000  # Stores port capacity in Mbit/s
            self.prev_bytes[switch_dpid][p.port_no] = p.tx_bytes

            # self.logger.info(f"Switch: {switch_dpid} Port: {p.port_no} Tx bytes: {p.tx_bytes} Bw: {self.bw[switch_dpid][p.port_no]}")

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        switch_dp = ev.switch.dp
        switch_dpid = switch_dp.id
        ofp_parser = switch_dp.ofproto_parser

        self.logger.info(f"Switch has been plugged in PID: {switch_dpid}")

        if switch_dpid not in self.switches:
            self.datapath_list[switch_dpid] = switch_dp
            self.switches.append(switch_dpid)

            self.run_check(ofp_parser, switch_dp)  # Thread function running in the background every 1s

    @set_ev_cls(event.EventSwitchLeave, MAIN_DISPATCHER)
    def switch_leave_handler(self, ev):
        switch = ev.switch.dp.id
        if switch in self.switches:
            try:
                self.switches.remove(switch)
                del self.datapath_list[switch]
                del self.neighbor[switch]
            except KeyError:
                self.logger.info(f"Switch has been already pulged off PID{switch}!")

    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def link_add_handler(self, ev):
        self.neighbor[ev.link.src.dpid][ev.link.dst.dpid] = ev.link.src.port_no
        self.neighbor[ev.link.dst.dpid][ev.link.src.dpid] = ev.link.dst.port_no
        self.logger.info(
            f"Link between switches has been established, SW1 DPID: {ev.link.src.dpid}:{ev.link.dst.port_no} SW2 DPID: {ev.link.dst.dpid}:{ev.link.dst.port_no}")

    @set_ev_cls(event.EventLinkDelete, MAIN_DISPATCHER)
    def link_delete_handler(self, ev):
        try:
            del self.neighbor[ev.link.src.dpid][ev.link.dst.dpid]
            del self.neighbor[ev.link.dst.dpid][ev.link.src.dpid]
        except KeyError:
            self.logger.info("Link has been already pluged off!")
            pass
