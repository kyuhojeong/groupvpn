#!/usr/bin/env python

import gvpn_controller as gc
import json
import os
import select
import signal
import socket
import subprocess
import sys
import threading
import time

logger = None

#CONFIG
CONFIG = gc.CONFIG

#thread signal
run_event = threading.Event()

tincan_bin = None
tincan_process = None

#exit handler and register this process
def exit_handler(signum, frame):
    if tincan_process is not None:
        tincan_process.send_signal(signal.SIGINT)
    run_event.clear()

class TinCanException(Exception):
    def __init__(self):
        Exception.__init__(self)
    def __str__(self):
        return str("tincane not running properly. terminate controller")

class UdpServer(gc.UdpServer):

    def serve(self, inactive_time):
        socks = select.select([self.sock], [], [], 0.3)
        if not socks[0]: #Check if the socks is empty
            if time.time() - inactive_time[0] > 60:
                raise TinCanException

        for sock in socks[0]:
            inactive_time[0] = time.time()
            data, addr = sock.recvfrom(CONFIG["buf_size"])
            if data[0] == '{':
                msg = json.loads(data)
                logger.debug("recv %s %s" % (addr, data))
                msg_type = msg.get("type", None)

                if msg_type == "local_state": self.state = msg
                elif msg_type == "peer_state": self.peers[msg["uid"]] = msg
                # we ignore connection status notification for now
                elif msg_type == "con_stat": pass
                elif msg_type == "con_req" or msg_type == "con_resp":
                    fpr_len = len(self.state["_fpr"])
                    fpr = msg["data"][:fpr_len]
                    cas = msg["data"][fpr_len + 1:]
                    ip4 = gc.get_ip4(msg["uid"], self.state["_ip4"])
                    self.create_connection(msg["uid"], fpr, 1, CONFIG["sec"],
                             cas, ip4)

    def run_server(self):
        global tincan_process
        global tincan_bin
        last_time = time.time()
        inactive_time = [time.time()]
        attempt = 0
        count = 0
        while run_event.is_set():
            try: 
                self.serve(inactive_time)
                time_diff = time.time() - last_time
                if time_diff > CONFIG["wait_time"]:
                    count += 1
                    self.trim_connections()
                    gc.do_get_state(self.sock)
                    last_time = time.time()
            except TinCanException:
                attempt += 1
                logger.debug("TinCan Failed {0} times".format(attempt));
                os.kill(tincan_process.pid, signal.SIGTERM)
                time.sleep(1)
                if attempt > 3:
                    logger.debug("TinCan Failed beyond threshold point");
                    run_event.clear()
                    break
                with open("core_log", "wb+") as core_log:
                    tincan_process = subprocess.Popen([tincan_bin],
                      stdout=subprocess.PIPE, stderr=core_log)
                    time.sleep(1)
                self.ctrl_conn_init()
                inactive_time[0] = time.time()
                pass

def main():

    signal.signal(signal.SIGINT, exit_handler)

    tincan_path = CONFIG["tincan_path"]
    global tincan_process
    global tincan_bin
    if os.path.exists(tincan_path):
        tincan_bin = os.path.abspath(tincan_path)
        with open("core_log", "w+") as core_log:
            logger.debug("Starting ipop-tincan");
            tincan_process = subprocess.Popen([tincan_bin], 
                       stdout=subprocess.PIPE, stderr=core_log)
            time.sleep(1)
    else:
        logger.debug("tincan binary doesn ot exist at specified directory")
        sys.exit(0)

    server = UdpServer(CONFIG["xmpp_username"], CONFIG["xmpp_password"],
                       CONFIG["xmpp_host"], CONFIG["ip4"])
    
    run_event.set()
    t = threading.Thread(target=server.run_server)
    t.deamon = True

    logger.debug("Starting Server");
    t.start()

    while t.isAlive():
        time.sleep(1)

if __name__  == '__main__':
    logger = gc.logging
    gc.ParseConfig() 
    main()
