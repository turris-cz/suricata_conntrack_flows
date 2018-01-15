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
import time

logging.basicConfig(stream=sys.stderr, level=logging.WARN)

output_lock=Lock()

def output_locked(line):
    output_lock.acquire()
    try:
        sys.stdout.write(line)
        if line[-1]!='\n':
            sys.stdout.write("\n")
        sys.stdout.flush()
    except IOError as e:
        os.unlink(sys.argv[1])
        sys.exit(1)
    output_lock.release()

def output_flow(json_dict):
    output_locked(json.dumps(json_dict)+"\n")

def flow_key(src_ip, dest_ip, src_port, dest_port, proto):
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
                key=flow_key(data["src_ip"], data["dest_ip"], data["src_port"], data["dest_port"], data["proto"])
                self.__active_flows[key]=data
            if self.__active_flows:
                logging.debug("getting conntrack...")
                with open("/proc/net/nf_conntrack") as f:
                    lines = f.readlines()
                    for line in lines:
                        if "mark=1" not in line: #prefilter, bypassed flows have connmark=1 TODO: make this configurable
                            continue
                        self.__parse_conntrack_line(line)
                to_delete=[]
                for key in self.__active_flows:
                    if self.__active_flows[key]["__seen__"]:
                        self.__active_flows[key]["__seen__"]=False
                    else:
                        logging.debug("bypassed flow closed: {}".format(str(self.__active_flows[key])))
                        self.__output_flow(self.__active_flows[key])
                        to_delete.append(key)
                for key in to_delete:
                    del self.__active_flows[key]
            self.__exit_cond.wait(5)
        for key in self.__active_flows.keys():
            self.__output_flow(self.__active_flows[key])

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
        #start = time.clock()
        matches = self.__pattern.search(line)
        #print("parsing took: {}".format((time.clock() - start)*1000))
        if not matches:
            logging.warn("cannot parse line: {}".format(line))
        key = flow_key(matches.group(1), matches.group(2), matches.group(3), matches.group(4), proto)
        if key in self.__active_flows:
            if not closed:
                self.__active_flows[key]["__seen__"]=True
                self.__active_flows[key]["flow"]["end"]=suricata_timestamp()
            self.__active_flows[key]["flow"]["pkts_toserver"]=matches.group(5)
            self.__active_flows[key]["flow"]["pkts_toclient"]=matches.group(7)
            self.__active_flows[key]["flow"]["bytes_toserver"]=matches.group(6)
            self.__active_flows[key]["flow"]["bytes_toclient"]=matches.group(8)

    def __output_flow(self, data):
        del data["__seen__"]
        data["timestamp"]=suricata_timestamp()
        output_flow(data)

    def add_new_flow(self, data):
        """add to queue __new_flows, they are moved to __active_flows in __run loop - to avoid locking __active_flows"""
        logging.debug("adding bypassed flow: {}".format(str(data)))
        data["__seen__"]=False
        self.__new_flows.put(data)

    def stop(self):
        self.__exit_cond.set()
        self.__thread.join()

    __pattern = re.compile(r'src=([0-9a-fA-F.:]+)\s+dst=([0-9a-fA-F.:]+)\s+sport=([0-9]+)\s+dport=([0-9]+)\s+packets=([0-9]+)\s+bytes=([0-9]+).*src=[0-9a-fA-F.:]+\s+dst=[0-9a-fA-F.:]+\s+sport=[0-9]+\s+dport=[0-9]+\s+packets=([0-9]+)\s+bytes=([0-9]+)')
    # some examples of conntrack lines, just to explain the regex: 
    # - "ipv4     2 udp      17 44 src=1.1.1.1 dst=2.2.2.2 sport=4321 dport=1234 packets=1 bytes=76 src=2.2.2.2 dst=1.1.1.1 sport=1234 dport=4321 packets=1 bytes=76 mark=0 use=2"
    # - "ipv4     2 udp      17 34 src=1.1.1.1 dst=255.255.255.255 sport=1234 dport=1234 packets=65 bytes=11895 [UNREPLIED] src=255.255.255.255 dst=1.1.1.1 sport=1234 dport=1234 packets=0 bytes=0 mark=0 use=2"
    # - "ipv4     2 tcp      6 6924 ESTABLISHED src=1.1.1.1 dst=2.2.2.2 sport=1234 dport=4321 packets=553 bytes=48091 src=2.2.2.2 dst=172.20.6.144 sport=4321 dport=1234 packets=358 bytes=48415 [ASSURED] mark=0 use=2"
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
        l = datagram.decode()
        if "bypassed" not in l: #prefilter, we are interested only in bypassed flows, don't even care about the rest
            output_locked(l)
            continue
        data = json.loads(l)
        if data["event_type"] == "flow" and "flow" in data:
            proto=data["proto"]
            if proto != "TCP" and proto != "UDP":
                output_locked(l)
                continue
            if data["flow"]["state"]!="bypassed":
                output_locked(l)
                continue
            if "bypass" in data["flow"]:
                del data["flow"]["bypass"]
            conn.add_new_flow(data)
        else: #if this is anything else then flow...
            output_locked(l) #...just resend immediatelly

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
