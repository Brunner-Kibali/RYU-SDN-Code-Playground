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
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

""" Working of a learning bridge/ Layer 2 Switch/ Ethernet Switch:
A "learning" bridge stores a database of the hosts its connected to, against it's ports. The hosts are identified by the MAC address of 
their network card, which looks like this: ab:cd:ef:12:34:56 (it's in hexadecimal). 

The ports are identified simply by their number. For example, a switch with 4 ports has port 1, 2, 3 and 4. 
If a switch receives a packet on its port 2, it will look at the destination MAC address 
(which host it's destined to) of that packet. It then looks into it's database to see if it knows which 
port is that host connected to. If it finds it out, it forwards that packet ONLY to that specific port. 

But if it doesn't have an entry in it's database yet, it floods that packet to ALL ports, and the hosts can check
for themselves if the packet was destined for them.

At the same time, the switch looks at the source MAC address of that packet, and it immediately knows that 
host X is located at port 2. It stores that entry in that database. 
So now you know that if the destination host replies to the source host, the switch won't have to flood the 
reply packet!"""


class SimpleSwitch13(app_manager.RyuApp):
    """ As an argument to the class, we pass ryu.base.app_manager.RyuApp import (imported in the first line).
    From the Ryu API handbook, app_manager class is the central management of Ryu applications.
    It loads Ryu applications, provide contexts to them and routes messages among Ryu applications."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

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

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
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
        """This is called when Ryu receives an OpenFlow packet_in message. When Ryu receives a packet_in message,
         a ofp_event.EventOFPPacketIn event is raised. The set_ev_cls decorator tells Ryu when the associated
         function, packet_in_handler should be called.

         The first argument of the set_ev_cls decorator indicates an event that makes function called.
         As you expect easily, every time a ofp_event.EventOFPPacketIn event is raised, this function is called.

         The second argument indicates the state of the switch when you want to allow Ryu to handle an event.
         Probably, you want to ignore OpenFlow packet_in messages before the handshake between Ryu and the switch
        finishes.

        Using MAIN_DISPATCHER as the second argument means this function is called only after the negotiation
        completes. MAIN_DISPATCHER denotes the normal state of the switch. During the initialization stage,
        the switch is in HANDSHAKE_DISPATCHER state!"""

        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg  # ev.msg is a data structure that contains the received packet.
        datapath = msg.datapath  # msg.dp is an object inside that data structure that represents a datapath (switch).
        ofproto = datapath.ofproto  # object that represents the OpenFlow protocol that Ryu and the switch negotiated.
        parser = datapath.ofproto_parser  # object that represents the OpenFlow protocol that Ryu and the switch negotiated.
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        # OFPActionOutput class is used with a packet_out message to specify a switch port that you want
        # to send the packet out of.
        actions = [parser.OFPActionOutput(out_port)]

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
        # OFPPacketOut class is used to build a packet_out message.
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        # By using datapath class's send_msg method, you can send an OpenFlow message object to the ports defined
        # in the actions variable.
        datapath.send_msg(out)

        # Events: You repeatedly saw the term event in the above code.
        # In event driven programming, the flow of the program is controlled by events, which are raised by
        # messages received by the system (e.g. EventOFPPacketIn is raised when the packet_in message is received
        # by Ryu from the (OpenFlow enabled) switch).
        #
        # We earlier discussed that OpenFlow is a protocol using which the controller (Ryu, PC) and the
        # infrastructure (or switch) communicate. Messages like packet_in are exactly what the communication
        # between the two looks like using the OpenFlow protocol!
