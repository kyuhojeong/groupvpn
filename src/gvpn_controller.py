#!/usr/bin/env python

import argparse
import getpass
import hashlib
import json
import logging
import random
import select
import socket 
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
    "svpn_port": 5800,
    "uid_size": 40,
    "sec": True,
    "wait_time": 30,
    "buf_size": 4096,
}

logging.basicConfig(level=logging.DEBUG)

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

def do_set_cb_endpoint(sock, addr):
    return make_call(sock, m="set_cb_endpoint", ip=addr[0], port=addr[1])

def do_register_service(sock, username, password, host):
    return make_call(sock, m="register_service", username=username,
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

def do_set_local_ip(sock, uid, ip4, ip6, ip4_mask=24, ip6_mask=64):
    return make_call(sock, m="set_local_ip", uid=uid, ip4=ip4, ip6=ip6,
                     ip4_mask=ip4_mask, ip6_mask=ip6_mask)

def do_set_remote_ip(sock, uid, ip4, ip6):
    return make_call(sock, m="set_remote_ip", uid=uid, ip4=ip4, ip6=ip6)

def do_get_state(sock):
    return make_call(sock, m="get_state")

def do_set_logging(sock):
    return make_call(sock, m="set_logging", flag=1)

class UdpServer:
    def __init__(self, user, password, host, ip4):
        self.state = {}
        self.peers = {}
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
        do_set_logging(self.sock)
        do_set_cb_endpoint(self.sock, self.sock.getsockname())
        do_set_local_ip(self.sock, self.uid, self.ip4, gen_ip6(self.uid))
        do_register_service(self.sock, self.user, self.password, self.host)
        do_get_state(self.sock)

    def create_connection(self, uid, data, nid, sec, cas, ip4):
        do_create_link(self.sock, uid, data, nid, sec, cas)
        do_set_remote_ip(self.sock, uid, ip4, gen_ip6(uid))

    def trim_connections(self):
        for k, v in self.peers.iteritems():
            if "fpr" in v and v["status"] == "offline":
                if v["last_time"] > CONFIG["wait_time"] * 2:
                    do_trim_link(self.sock, k)

    def serve(self):
        socks = select.select([self.sock], [], [], CONFIG["wait_time"])
        for sock in socks[0]:
            data, addr = sock.recvfrom(CONFIG["buf_size"])
            if data[0] == '{':
                msg = json.loads(data)
                logging.debug("recv %s %s" % (addr, data))
                msg_type = msg.get("type", None)

                if msg_type == "local_state": self.state = msg
                elif msg_type == "peer_state": self.peers[msg["uid"]] = msg
                # we ignore connection status notification for now
                elif msg_type == "con_stat": pass
                elif msg_type == "con_req" or msg_type == "con_resp":
                    fpr_len = len(self.state["_fpr"])
                    fpr = msg["data"][:fpr_len]
                    cas = msg["data"][fpr_len + 1:]
                    ip4 = self.uid_ip_table[msg["uid"]]
                    self.create_connection(msg["uid"], fpr, 1, CONFIG["sec"],
                             cas, ip4)

def parse_config():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", help="load configuration from a file",
                        dest="config_file", metavar="config_file")
    args = parser.parse_args()

    if args.config_file:
        # Load the config file
        logging.debug("Loading config file %s" % args.config_file)
        with open(args.config_file) as f:
            loaded_config = json.load(f)
        CONFIG.update(loaded_config)
    logging.debug("Configuration:\n%s" % CONFIG)

    if not ("xmpp_username" in CONFIG and "xmpp_host" in CONFIG):
        raise ValueError("At least 'xmpp_username' and 'xmpp_host' must be "
                         "specified in config file")

    if "xmpp_password" not in CONFIG:
        prompt = "\nPassword for %s: " % CONFIG["xmpp_username"]
        CONFIG["xmpp_password"] = getpass.getpass(prompt)

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

