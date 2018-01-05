#!/usr/bin/python3
#
#    DevDetect - small utility to detect new devices on local network
#    Copyright (C) 2017 CZ.NIC, z.s.p.o. (http://www.nic.cz/)
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# author Martin Petracek, <martin.petracek@nic.cz>
#
# When suricata bypass is enabled, flows information (packets/bytes counts and end timestamp) aren't always right.
# When flow is bypassed, suricata reports it as closed (with state="bypassed") and don't care about it anymore.
# This script does the accounting of bypassed flows, it doesn't output them immediatelly, it keeps them until they are really closed.
# It utilizes conntrack, kernel module for connection tracking. It monitors conntrack output to find out the counters and flow end time.
#
# To use it, just point suricata "flow" output to UNIX-DGRAM socket and run this script with that path as argv[1].
# This script acts like "proxy", it ouputs flows (to stdout) in suricata json format, just with updated counters.
# All other suricata events are passed to output immediatelly.

import socket
import json
import string
import sys
import os
import signal
from datetime import datetime, timezone
import re
import logging
import queue
from threading import Thread, Event, Lock

logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)

output_lock=Lock()

def send_line(line):
    output_lock.acquire()
    try:
        print(line)
    except IOError as e:
        os.unlink(sys.argv[1])
        sys.exit(1)
    output_lock.release()

def send_flow(json_dict):
    send_line(json.dumps(json_dict))

def hash_flow(src_ip, dest_ip, src_port, dest_port, proto):
    return str(proto.upper())+":"+src_ip+":"+str(src_port)+"->"+dest_ip+":"+str(dest_port)

def suricata_timestamp():
    #should return current timestamp in suricata format. Eg. '2017-09-08T13:52:25.821230+0200'
    return str(datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%dT%H:%M:%S.%f%z"))

class Conntrack_flows:
    """stores bypassed flows, periodically checks their counters"""
    """when these flows are closed (or disappear from conntrack), they are sent to output and removed from here"""
    """flows to check are added from main thread (using add_new_flow()), after that they are treated completely by this class"""
    def run(self):
        self.__thread = Thread(target = self.__run)
        self.__thread.start()

    def __run(self):
        """checks periodically conntrack (/proc/net/conntrack)"""
        """in the main loop, 3 things are done:
         - new flows moved from __new_flows to __active_flows
         - conntrack is read and parsed (each line passed to __parse_conntrack_line()) - also sets __seen__ to flows updated in this loop
         - flows with __seen__ = False are outputed and deleted from __active_flows, __seen__ flag is reset for the next loop
         """
        while not self.__exit_cond.is_set():
            while not self.__new_flows.empty():
                data=self.__new_flows.get()
                key=hash_flow(data["src_ip"], data["dest_ip"], data["src_port"], data["dest_port"], data["proto"])
                self.__active_flows[key]=data
            if self.__active_flows:
                logging.debug("getting conntrack...")
                with open("/proc/net/nf_conntrack") as f:
                    lines = f.readlines()
                    for line in lines:
                        if "mark=1" not in line: #TODO: make prefilter configurable
                            continue
                        self.__parse_conntrack_line(line)
                to_delete=[]
                for key in self.__active_flows:
                    if self.__active_flows[key]["__seen__"]:
                        self.__active_flows[key]["__seen__"]=False
                    else:
                        logging.debug("bypassed flow closed: {}".format(str(self.__active_flows[key])))
                        del self.__active_flows[key]["__seen__"]
                        send_flow(self.__active_flows[key])
                        to_delete.append(key)
                for key in to_delete:
                    del self.__active_flows[key]
            self.__exit_cond.wait(5)
        for key in self.__active_flows.keys():
            del self.__active_flows[key]["__seen__"]
            send_flow(self.__active_flows[key])

    def __parse_conntrack_line(self, line):
        """parses one line of conntrack - tries to match it to flow from __active_flows and update counters, timestamps and set __seen__ flag to True"""
        """closed flows (TIME_WAIT) are treated as disappeared - counters are updated, but __seen__ is not set -> they will be removed at the end of this loop"""
        if "tcp" in line:
            proto="TCP"
            if "TIME_WAIT" in line:
                closed=True
            else:
                closed=False
        elif "udp" in line:
            proto="UDP"
            closed=False
        else:
            return
        matches = self.__pattern.findall(line)
        if len(matches)<2:
            logger.warn("cannot parse line: {}".format(line))
        key1 = hash_flow(matches[0][0], matches[0][1], matches[0][2], matches[0][3], proto)
        key2 = hash_flow(matches[1][0], matches[1][1], matches[1][2], matches[1][3], proto)
        if key1 in self.__active_flows:
            if not closed:
                self.__active_flows[key1]["__seen__"]=True
            self.__active_flows[key1]["timestamp"]=suricata_timestamp()
            self.__active_flows[key1]["flow"]["pkts_toserver"]=matches[0][4]
            self.__active_flows[key1]["flow"]["pkts_toclient"]=matches[1][4]
            self.__active_flows[key1]["flow"]["bytes_toserver"]=matches[0][5]
            self.__active_flows[key1]["flow"]["bytes_toclient"]=matches[1][5]
        elif key2 in self.__active_flows:
            if not closed:
                self.__active_flows[key2]["__seen__"]=True
            self.__active_flows[key2]["timestamp"]=suricata_timestamp()
            self.__active_flows[key2]["flow"]["pkts_toserver"]=matches[1][4]
            self.__active_flows[key2]["flow"]["pkts_toclient"]=matches[0][4]
            self.__active_flows[key2]["flow"]["bytes_toserver"]=matches[1][5]
            self.__active_flows[key2]["flow"]["bytes_toclient"]=matches[0][5]

    def add_new_flow(self, data):
        """add to queue __new_flows, they are moved to __active_flows in __run loop - to avoid locking __active_flows"""
        logging.debug("adding bypassed flow: {}".format(str(data)))
        data["__seen__"]=False
        self.__new_flows.put(data)

    def stop(self):
        self.__exit_cond.set()
        self.__thread.join()

    __pattern = re.compile(r'src=([0-9a-fA-F.:]+)\s+dst=([0-9a-fA-F.:]+)\s+sport=([0-9]+)\s+dport=([0-9]+)\s+packets=([0-9]+)\s+bytes=([0-9]+)')
    # conntrack lines are in form: "ipv4     2 udp      17 44 src=1.1.1.1 dst=2.2.2.2 sport=4321 dport=1234 packets=1 bytes=76 src=2.2.2.2 dst=1.1.1.1 sport=1234 dport=4321 packets=1 bytes=76 mark=0 use=2"
    # there are 2 matches of this pattern. Note that there can be different addresses in both directions - due to NAT
    __new_flows = queue.Queue()
    __exit_cond = Event()
    __active_flows = {}
    __thread = None

conn = Conntrack_flows()

#this reads socket from suricata and when it sees "flow" report with "state"="bypassed", it adds it into Conntrack_flows (and doesn't output anything immediatelly)
#all other reports are outputed immediatelly
def suricata_get_flow(recv_socket_path):
    try:
        os.unlink(recv_socket_path) #remove stray socket
    except OSError:
        pass
    recv_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    recv_socket.bind(recv_socket_path)
    while True:
        datagram = recv_socket.recv(2048)
        if not datagram:
            continue
        lines = datagram.decode().split('\n')
        for l in lines:
            if not l:
                break
            data = json.loads(l)
            if data["event_type"] == "flow" and "flow" in data:
                proto=data["proto"]
                if proto != "TCP" and proto != "UDP":
                    send_line(l)
                    continue
                if data["flow"]["state"]!="bypassed":
                    send_line(l)
                    continue
                if "bypass" in data["flow"]:
                    del data["flow"]["bypass"]
                conn.add_new_flow(data)
            else: #if this is anything else then flow...
                send_line(l) #...just resend immediatelly

def exit_gracefully(signum, frame):
    logging.debug("asked to quit, sending all remaining flows")
    conn.stop()
    os.unlink(sys.argv[1])
    sys.exit(0)

def main():
    if len(sys.argv) < 2:
        logging.error("usage: {} recv_socket".format(sys.argv[0]))
        return 1
    conn.run()
    signal.signal(signal.SIGINT, exit_gracefully)
    signal.signal(signal.SIGTERM, exit_gracefully)
    suricata_get_flow(sys.argv[1])

if __name__ == "__main__":
    main()
