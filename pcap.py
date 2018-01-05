#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# pcap.py - Saves messages from pcap files in Redis.
#
# Copyright (c) Addy Yeow Chin Heng <ayeowch@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

"""
Saves messages from pcap files in Redis.
"""

import bisect
import dpkt
import glob
import hashlib
import logging
import os
import socket
import sys
import time
from binascii import unhexlify
from collections import defaultdict
from ConfigParser import ConfigParser
from Queue import PriorityQueue

from protocol import (
    HeaderTooShortError,
    PayloadTooShortError,
    ProtocolError,
    Serializer,
)
from utils import new_redis_conn

REDIS_CONN = None
CONF = {}


class Stream(object):
    """
    Implements a stream object with generator function to iterate over the
    queued segments while keeping track of captured timestamp.
    """
    def __init__(self, segments=None):
        self.segments = segments
        self.timestamp = 0  # in ms

    def data(self):
        """
        Generator to iterate over the segments in this stream. Duplicated
        segments are ignored.
        """
        seqs = set()
        while not self.segments.empty():
            (self.timestamp, tcp_pkt) = self.segments.get()[1]
            if tcp_pkt.seq in seqs:
                continue
            yield tcp_pkt.data
            seqs.add(tcp_pkt.seq)


class Cache(object):
    """
    Implements caching mechanic to cache messages from pcap file in Redis.
    """
    def __init__(self, filepath):
        self.filepath = filepath
        self.redis_pipe = REDIS_CONN.pipeline()
        self.serializer = Serializer(magic_number=CONF['magic_number'])
        self.streams = defaultdict(PriorityQueue)
        self.stream = Stream()
        self.count = 0
        self.ping_keys = set()  # ping:ADDRESS-PORT:NONCE
        self.invs = defaultdict(list)

    def cache_messages(self):
        """
        Reconstructs messages from TCP streams and caches them in Redis.
        """
        try:
            self.extract_streams()
        except dpkt.dpkt.NeedData:
            logging.warning("Need data: %s", self.filepath)
        for stream_id, self.stream.segments in self.streams.iteritems():
            data = self.stream.data()
            _data = data.next()
            while True:
                try:
                    (msg, _data) = self.serializer.deserialize_msg(_data)
                except (HeaderTooShortError, PayloadTooShortError) as err:
                    logging.debug("%s: %s", stream_id, err)
                    try:
                        _data += data.next()
                    except StopIteration:
                        break
                except ProtocolError as err:
                    logging.debug("%s: %s", stream_id, err)
                    try:
                        _data = data.next()
                    except StopIteration:
                        break
                else:
                    src = (stream_id[0], stream_id[1])
                    dst = (stream_id[2], stream_id[3])
                    node = src
                    if src == CONF['tor_proxy']:
                        node = dst
                    self.cache_message(node, self.stream.timestamp, msg)
        self.redis_pipe.execute()
        self.cache_rtt()

    def extract_streams(self):
        """
        Extracts TCP streams with data from the pcap file. TCP segments in
        each stream are queued according to their sequence number.
        """
        with open(self.filepath) as pcap_file:
            pcap_reader = dpkt.pcap.Reader(pcap_file)
            for timestamp, buf in pcap_reader:
                try:
                    frame = dpkt.ethernet.Ethernet(buf)
                except dpkt.dpkt.UnpackError:
                    continue
                ip_pkt = frame.data
                if (not isinstance(ip_pkt, dpkt.ip.IP) and
                        not isinstance(ip_pkt, dpkt.ip6.IP6)):
                    continue
                if not isinstance(ip_pkt.data, dpkt.tcp.TCP):
                    continue
                ip_ver = socket.AF_INET
                if ip_pkt.v == 6:
                    ip_ver = socket.AF_INET6
                tcp_pkt = ip_pkt.data
                stream_id = (
                    socket.inet_ntop(ip_ver, ip_pkt.src),
                    tcp_pkt.sport,
                    socket.inet_ntop(ip_ver, ip_pkt.dst),
                    tcp_pkt.dport
                )
                if len(tcp_pkt.data) > 0:
                    timestamp = int(timestamp * 1000)  # in ms
                    self.streams[stream_id].put(
                        (tcp_pkt.seq, (timestamp, tcp_pkt)))
        logging.info("Streams: %d", len(self.streams))

    def cache_message(self, node, timestamp, msg):
        """
        Caches inv/pong message from the specified node.
        """
        if msg['command'] not in ["inv", "pong"]:
            return

        if node[0] == "127.0.0.1":
            # Restore .onion node
            onion_node = REDIS_CONN.get("onion:{}".format(node[1]))
            if onion_node:
                node = eval(onion_node)

        if msg['command'] == "inv":
            invs = 0
            for inv in msg['inventory']:
                key = "inv:{}:{}".format(inv['type'], inv['hash'])
                if (len(self.invs[key]) >= CONF['inv_count'] and
                        timestamp > self.invs[key][0]):
                    logging.debug("Skip: %s (%d)", key, timestamp)
                    continue
                bisect.insort(self.invs[key], timestamp)
                if inv['type'] == 2:
                    # Redis key for reference (first seen) block inv
                    rkey = "r{}".format(key)
                    rkey_ms = REDIS_CONN.get(rkey)
                    if rkey_ms is None:
                        REDIS_CONN.set(rkey, timestamp)
                        self.redis_pipe.set("lastblockhash", inv['hash'])
                    elif (timestamp - int(rkey_ms)) / 1000 > CONF['ttl']:
                        # Ignore block inv first seen more than 3 hours ago
                        logging.debug("Skip: %s (%d)", key, timestamp)
                        continue
                invs += 1
                self.redis_pipe.zadd(key, timestamp, self.node_hash(node))
                self.redis_pipe.expire(key, CONF['ttl'])
            self.count += invs
        elif msg['command'] == "pong":
            key = "ping:{}-{}:{}".format(node[0], node[1], msg['nonce'])
            self.redis_pipe.rpushx(key, timestamp)
            self.ping_keys.add(key)
            self.count += 1

    def node_hash(self, node):
        """
        Encodes a tuple of address and port in shorten hash for storage in
        Redis.
        """
        return hashlib.sha256('%s-%d' % node).hexdigest()[:8]

    def cache_rtt(self):
        """
        Calculates round-trip time (RTT) values and caches them in Redis.
        """
        for key in self.ping_keys:
            timestamps = REDIS_CONN.lrange(key, 0, 1)
            if len(timestamps) > 1:
                rtt_key = "rtt:{}".format(':'.join(key.split(":")[1:-1]))
                rtt = int(timestamps[1]) - int(timestamps[0])  # pong - ping
                logging.debug("%s: %d", rtt_key, rtt)
                self.redis_pipe.lpush(rtt_key, rtt)
                self.redis_pipe.ltrim(rtt_key, 0, CONF['rtt_count'] - 1)
                self.redis_pipe.expire(rtt_key, CONF['ttl'])
        self.redis_pipe.execute()


def cron():
    """
    Periodically fetches oldest pcap file to extract messages from.
    """
    while True:
        time.sleep(0.1)

        try:
            oldest = min(glob.iglob("{}/*.pcap".format(CONF['pcap_dir'])))
        except ValueError as err:
            logging.warning(err)
            continue
        latest = max(glob.iglob("{}/*.pcap".format(CONF['pcap_dir'])))
        if oldest == latest:
            continue
        tmp = oldest
        dump = tmp.replace(".pcap", ".pcap_")
        try:
            os.rename(tmp, dump)  # Mark file as being read
        except OSError as err:
            logging.warning(err)
            continue

        logging.info("Loading: %s", dump)

        start = time.time()
        cache = Cache(filepath=dump)
        cache.cache_messages()
        end = time.time()
        elapsed = end - start

        logging.info("Dump: %s (%d messages)", dump, cache.count)
        logging.info("Elapsed: %d", elapsed)

        os.remove(dump)


def init_conf(argv):
    """
    Populates CONF with key-value pairs from configuration file.
    """
    conf = ConfigParser()
    conf.read(argv[1])
    CONF['logfile'] = conf.get('pcap', 'logfile')
    CONF['magic_number'] = unhexlify(conf.get('pcap', 'magic_number'))
    CONF['db'] = conf.getint('pcap', 'db')
    CONF['debug'] = conf.getboolean('pcap', 'debug')
    CONF['ttl'] = conf.getint('pcap', 'ttl')
    CONF['rtt_count'] = conf.getint('pcap', 'rtt_count')
    CONF['inv_count'] = conf.getint('pcap', 'inv_count')

    tor_proxy = conf.get('pcap', 'tor_proxy').split(":")
    CONF['tor_proxy'] = (tor_proxy[0], int(tor_proxy[1]))

    CONF['pcap_dir'] = conf.get('pcap', 'pcap_dir')
    if not os.path.exists(CONF['pcap_dir']):
        os.makedirs(CONF['pcap_dir'])


def main(argv):
    if len(argv) < 2 or not os.path.exists(argv[1]):
        print("Usage: pcap.py [config]")
        return 1

    # Initialize global conf
    init_conf(argv)

    # Initialize logger
    loglevel = logging.INFO
    if CONF['debug']:
        loglevel = logging.DEBUG

    logformat = ("[%(process)d] %(asctime)s,%(msecs)05.1f %(levelname)s "
                 "(%(funcName)s) %(message)s")
    logging.basicConfig(level=loglevel,
                        format=logformat,
                        filename=CONF['logfile'],
                        filemode='a')
    print("Log: {}, press CTRL+C to terminate..".format(CONF['logfile']))

    global REDIS_CONN
    REDIS_CONN = new_redis_conn(db=CONF['db'])

    cron()

    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
