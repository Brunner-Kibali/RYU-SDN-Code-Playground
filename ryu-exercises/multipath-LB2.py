# coding=utf-8
def send_group_mod(self, datapath):
    ofp = datapath.ofproto
    ofp_parser = datapath.ofproto_parser

    port_1 = 3
    queue_1 = ofp_parser.OFPActionSetQueue(0)
    actions_1 = [queue_1, ofp_parser.OFPActionOutput(port_1)]

    port_2 = 2
    queue_2 = ofp_parser.OFPActionSetQueue(0)
    actions_2 = [queue_2, ofp_parser.OFPActionOutput(port_2)]

    weight_1 = 50
    weight_2 = 50

    watch_port = ofproto_v1_3.OFPP_ANY
    watch_group = ofproto_v1_3.OFPQ_ALL

    buckets = [
        ofp_parser.OFPBucket(weight_1, watch_port, watch_group, actions_1),
        ofp_parser.OFPBucket(weight_2, watch_port, watch_group, actions_2)]

    group_id = 50
    req = ofp_parser.OFPGroupMod(
        datapath, ofp.OFPFC_ADD,
        ofp.OFPGT_SELECT, group_id, buckets)

    datapath.send_msg(req)
