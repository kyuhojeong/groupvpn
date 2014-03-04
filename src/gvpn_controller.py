#!/usr/bin/env python

import argparse
import getpass
import hashlib
import json
import logging
import random
import select
import socket 
import struct
import sys
import time

# Set default config values
CONFIG = {
    "stun": ["stun.l.google.com:19302", "stun1.l.google.com:19302",
             "stun2.l.google.com:19302", "stun3.l.google.com:19302",
             "stun4.l.google.com:19302"],
    "turn": [],  # Contains dicts with "server", "user", "pass" keys
    "ip4": "172.16.0.1",
    "localhost": "127.0.0.1",
    "ip6_prefix": "fd50:0dbc:41f2:4a3c",
    "localhost6": "::1",
    "ip4_mask": 24,
    "ip6_mask": 64,
    "subnet_mask": 32,
    "svpn_port": 5800,
    "uid_size": 40,
    "sec": True,
    "wait_time": 15,
    "buf_size": 4096,
    "tincan_logging": 1,
    "controller_logging" : "INFO",
    "router_mode": False,
    "on-demand_connection" : False,
    "on-demand_inactive_timeout" : 600
}

def gen_ip6(uid, ip6=None):
    if ip6 is None:
        ip6 = CONFIG["ip6_prefix"]
    for i in range(0, 16, 4): ip6 += ":" + uid[i:i+4]
    return ip6

def gen_uid(ip4):
    return hashlib.sha1(ip4).hexdigest()[:CONFIG["uid_size"]]

def make_call(sock, **params):
    if socket.has_ipv6: dest = (CONFIG["localhost6"], CONFIG["svpn_port"])
    else: dest = (CONFIG["localhost"], CONFIG["svpn_port"])
    return sock.sendto(json.dumps(params), dest)

def do_send_msg(sock, method, overlay_id, uid, data):
    return make_call(sock, m=method, overlay_id=overlay_id, uid=uid, data=data)

def do_set_cb_endpoint(sock, addr):
    return make_call(sock, m="set_cb_endpoint", ip=addr[0], port=addr[1])

def do_register_service(sock, username, password, host):
    return make_call(sock, m="register_svc", username=username,
                     password=password, host=host)

def do_create_link(sock, uid, fpr, overlay_id, sec, cas, stun=None, turn=None):
    if stun is None:
        stun = random.choice(CONFIG["stun"])
    if turn is None:
        if CONFIG["turn"]:
            turn = random.choice(CONFIG["turn"])
        else:
            turn = {"server": "", "user": "", "pass": ""}
    return make_call(sock, m="create_link", uid=uid, fpr=fpr,
                     overlay_id=overlay_id, stun=stun, turn=turn["server"],
                     turn_user=turn["user"],
                     turn_pass=turn["pass"], sec=sec, cas=cas)

def do_trim_link(sock, uid):
    return make_call(sock, m="trim_link", uid=uid)

def do_set_local_ip(sock, uid, ip4, ip6, ip4_mask, ip6_mask, subnet_mask):
    return make_call(sock, m="set_local_ip", uid=uid, ip4=ip4, ip6=ip6,
                     ip4_mask=ip4_mask, ip6_mask=ip6_mask,
                     subnet_mask=subnet_mask)

def do_set_remote_ip(sock, uid, ip4, ip6):
    return make_call(sock, m="set_remote_ip", uid=uid, ip4=ip4, ip6=ip6)

def do_get_state(sock):
    return make_call(sock, m="get_state", stats=True)

def do_set_logging(sock, logging):
    return make_call(sock, m="set_logging", logging=logging)

class UdpServer:
    def __init__(self, user, password, host, ip4):
        self.state = {}
        self.idle_peers = {}
        self.peers = {}
        self.conn_stat = {}
        self.user = user
        self.password = password
        self.host = host
        self.ip4 = ip4
        self.uid = gen_uid(ip4)
        if socket.has_ipv6:
            self.sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        else:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("", 0))
        self.ctrl_conn_init()

        self.uid_ip_table = {}
        parts = CONFIG["ip4"].split(".")
        ip_prefix = parts[0] + "." + parts[1] + "."
        for i in range(0, 255):
            for j in range(0, 255):
                ip = ip_prefix + str(i) + "." + str(j)
                uid = gen_uid(ip)
                self.uid_ip_table[uid] = ip

    def ctrl_conn_init(self):
        do_set_logging(self.sock, CONFIG["tincan_logging"])
        do_set_cb_endpoint(self.sock, self.sock.getsockname())

        if not CONFIG["router_mode"]:
            do_set_local_ip(self.sock, self.uid, self.ip4, gen_ip6(self.uid),
                             CONFIG["ip4_mask"], CONFIG["ip6_mask"],
                             CONFIG["subnet_mask"])
        else:
            do_set_local_ip(self.sock, self.uid, CONFIG["router_ip"],
                           gen_ip6(self.uid), CONFIG["router_ip4_mask"],
                           CONFIG["router_ip6_mask"], CONFIG["subnet_mask"])

        do_register_service(self.sock, self.user, self.password, self.host)
        do_get_state(self.sock)

    def create_connection(self, uid, data, nid, sec, cas, ip4):
        do_create_link(self.sock, uid, data, nid, sec, cas)
        do_set_remote_ip(self.sock, uid, ip4, gen_ip6(uid))

    def trim_connections(self):
        for k, v in self.peers.iteritems():
            if "fpr" in v and v["status"] == "offline":
                if v["last_time"] > CONFIG["wait_time"] * 2:
                    do_send_msg(self.sock, "send_msg", 1, k,
                                "destroy" + self.state["_uid"])
                    do_trim_link(self.sock, k)
            if CONFIG["on-demand_connection"] and v["status"] == "online": 
                if v["last_active"] + CONFIG["on-demand_inactive_timeout"]\
                                                              < time.time():
                    logging.debug("Inactive, trimming node:{0}".format(k))
                    do_send_msg(self.sock, 1, "send_msg", k,
                                "destroy" + self.state["_uid"])
                    do_trim_link(self.sock, k)
 
    def ondemand_create_connection(self, uid, send_req):
        logging.debug("idle peers {0}".format(self.idle_peers))
        peer = self.idle_peers[uid]
        fpr_len = len(self.state["_fpr"])
        fpr = peer["data"][:fpr_len]
        cas = peer["data"][fpr_len + 1:]
        ip4 = self.uid_ip_table[peer["uid"]]
        logging.debug("Start mutual creating connection")
        if send_req:
            do_send_msg(self.sock, "send_msg", 1, uid, fpr)
        self.create_connection(peer["uid"], fpr, 1, CONFIG["sec"], cas, ip4)

    def create_connection_req(self, data):
        version_ihl = struct.unpack('!B', data[54:55])
        version = version_ihl[0] >> 4
        if version == 4:
            s_addr = socket.inet_ntoa(data[66:70])
            d_addr = socket.inet_ntoa(data[70:74])
        elif version == 6:
            s_addr = socket.inet_ntop(socket.AF_INET6, data[62:78])
            d_addr = socket.inet_ntop(socket.AF_INET6, data[78:94])
            # At present, we do not handle ipv6 multicast
            if d_addr.startswith("ff02"):
                return

        uid = gen_uid(d_addr)
        try:
            msg = self.idle_peers[uid]
        except KeyError:
            logging.error("Peer {0} is not logged in".format(d_addr))
            return
        logging.debug("idle_peers[uid] --- {0}".format(msg))
        self.ondemand_create_connection(uid, send_req=True)

    def trigger_conn_request(self, peer):
        if "fpr" not in peer and peer["xmpp_time"] < CONFIG["wait_time"] * 8:
            self.conn_stat[peer["uid"]] = "req_sent"
            do_send_msg(self.sock, "con_req", 1, peer["uid"],
                        self.state["_fpr"]);

    def check_collision(self, msg_type, uid):
        if msg_type == "con_req" and \
           self.conn_stat.get(uid, None) == "req_sent":
            if uid > self.state["_uid"]:
                do_trim_link(self.sock, uid)
                self.conn_stat.pop(uid, None)
                return False
        elif msg_type == "con_resp":
            self.conn_stat[uid] = "resp_recv"
            return False
        else:
            return True

    def serve(self):
        socks = select.select([self.sock], [], [], CONFIG["wait_time"])
        for sock in socks[0]:
            data, addr = sock.recvfrom(CONFIG["buf_size"])
            if data[0] == '{':
                msg = json.loads(data)
                logging.debug("recv %s %s" % (addr, data))
                msg_type = msg.get("type", None)

                if msg_type == "local_state":
                    self.state = msg
                elif msg_type == "peer_state": 
                    if msg["status"] == "offline" or "stats" not in msg:
                        self.peers[msg["uid"]] = msg
                        self.trigger_conn_request(msg)
                        continue
                    stats = msg["stats"]
                    total_byte = 0
                    for stat in stats:
                        total_byte += stat["sent_total_bytes"]
                        total_byte += stat["recv_total_bytes"]
                    msg["total_byte"]=total_byte
                    logging.debug("self.peers:{0}".format(self.peers))
                    if not msg["uid"] in self.peers:
                        msg["last_active"]=time.time()
                    elif not "total_byte" in self.peers[msg["uid"]]:
                        msg["last_active"]=time.time()
                    else:
                        if msg["total_byte"] > \
                                        self.peers[msg["uid"]]["total_byte"]:
                            msg["last_active"]=time.time()
                        else:
                            msg["last_active"]=\
                                         self.peers[msg["uid"]]["last_active"]
                    self.peers[msg["uid"]] = msg

                # we ignore connection status notification for now
                elif msg_type == "con_stat": pass
                elif msg_type == "con_req": 
                    if CONFIG["on-demand_connection"]: 
                        self.idle_peers[msg["uid"]]=msg
                    else:
                        if self.check_collision(msg_type,msg["uid"]): continue
                        fpr_len = len(self.state["_fpr"])
                        fpr = msg["data"][:fpr_len]
                        cas = msg["data"][fpr_len + 1:]
                        ip4 = self.uid_ip_table[msg["uid"]]
                        self.create_connection(msg["uid"], fpr, 1, CONFIG["sec"],
                              cas, ip4)
                elif msg_type == "con_resp":
                    if self.check_collision(msg_type, msg["uid"]): continue
                    fpr_len = len(self.state["_fpr"])
                    fpr = msg["data"][:fpr_len]
                    cas = msg["data"][fpr_len + 1:]
                    ip4 = self.uid_ip_table[msg["uid"]]
                    self.create_connection(msg["uid"], fpr, 1, CONFIG["sec"],
                          cas, ip4)

                # send message is used as "request for start mutual connection"
                elif msg_type == "send_msg": 
                    if CONFIG["on-demand_connection"]:
                        if msg["data"].startswith("destroy"):
                            do_trim_link(self.sock, msg["uid"])
                        else:
                            self.ondemand_create_connection(msg["uid"], False)
               
            # If a packet that is destined to yet no p2p connection established
            # node, the packet as a whole is forwarded to controller
            else:
                if not CONFIG["on-demand_connection"]:
                    return
                if len(data) < 16:
                    return
                self.create_connection_req(data)

def parse_config():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", help="load configuration from a file",
                        dest="config_file", metavar="config_file")
    args = parser.parse_args()

    if args.config_file:
        # Load the config file
        with open(args.config_file) as f:
            loaded_config = json.load(f)
        CONFIG.update(loaded_config)

    if not ("xmpp_username" in CONFIG and "xmpp_host" in CONFIG):
        raise ValueError("At least 'xmpp_username' and 'xmpp_host' must be "
                         "specified in config file")

    if "xmpp_password" not in CONFIG:
        prompt = "\nPassword for %s: " % CONFIG["xmpp_username"]
        CONFIG["xmpp_password"] = getpass.getpass(prompt)

    if "controller_logging" in CONFIG:
        level = getattr(logging, CONFIG["controller_logging"])
        logging.basicConfig(level=level)

def main():

    parse_config()
    count = 0
    server = UdpServer(CONFIG["xmpp_username"], CONFIG["xmpp_password"],
                       CONFIG["xmpp_host"], CONFIG["ip4"])
    last_time = time.time()
    while True:
        server.serve()
        time_diff = time.time() - last_time
        if time_diff > CONFIG["wait_time"]:
            count += 1
            server.trim_connections()
            do_get_state(server.sock)
            last_time = time.time()

if __name__ == "__main__":
    main()

