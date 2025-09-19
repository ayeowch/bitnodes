#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# pcap.py - Base class to save messages from pcap files in Redis.
#
# Copyright (c) Bitnodes <info@bitnodes.io>
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
Base class to save messages from pcap files in Redis.
"""

import glob
import logging
import os
import socket
import time
from collections import defaultdict
from queue import PriorityQueue

import dpkt

from protocol import (
    HeaderTooShortError,
    PayloadTooShortError,
    ProtocolError,
    Serializer,
)


class Stream(object):
    """
    Implement a stream object with generator function to iterate over the
    queued segments while keeping track of captured timestamp.
    """

    def __init__(self, segments=None):
        self.segments = segments
        self.timestamp = 0  # milliseconds

    def data(self):
        """
        Generator to iterate over the segments in this stream. Duplicated
        segments are ignored.
        """
        seqs = set()
        while not self.segments.empty():
            (seq, (self.timestamp, tcp_pkt_data)) = self.segments.get()
            if seq in seqs:
                continue
            yield tcp_pkt_data
            seqs.add(seq)


class Cache(object):
    """
    Base caching mechanic to cache messages from pcap file in Redis.
    """

    def __init__(self, filepath, magic_number=None, tor_proxies=None, redis_conn=None):
        self.start_t = time.time()
        self.filepath = filepath
        self.tor_proxies = tor_proxies or []
        self.redis_conn = redis_conn
        if redis_conn:
            self.redis_pipe = redis_conn.pipeline()
        else:
            self.redis_pipe = None
        self.serializer = Serializer(magic_number=magic_number)
        self.streams = defaultdict(PriorityQueue)
        self.stream = Stream()

    def __del__(self):
        logging.debug(f"Elapsed: {time.time() - self.start_t}")

    def extract_streams(self):
        """
        Extract TCP streams with data from the pcap file. TCP segments in
        each stream are queued according to their sequence number.
        """
        with open(self.filepath, "rb") as pcap_file:
            pcap_reader = dpkt.pcap.Reader(pcap_file)
            for timestamp, buf in pcap_reader:
                try:
                    frame = dpkt.ethernet.Ethernet(buf)
                except dpkt.dpkt.UnpackError:
                    continue
                ip_pkt = frame.data
                if not isinstance(ip_pkt, dpkt.ip.IP) and not isinstance(
                    ip_pkt, dpkt.ip6.IP6
                ):
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
                    tcp_pkt.dport,
                )
                if len(tcp_pkt.data) > 0:
                    timestamp = int(timestamp * 1000)  # milliseconds
                    self.streams[stream_id].put(
                        (tcp_pkt.seq, (timestamp, tcp_pkt.data))
                    )

        logging.debug(f"Streams: {len(self.streams)}")

    def cache_messages(self):
        """
        Reconstruct messages from TCP streams and cache them in Redis.
        """
        try:
            self.extract_streams()
        except dpkt.dpkt.NeedData:
            logging.warning(f"Need data: {self.filepath}")
        for stream_id, self.stream.segments in self.streams.items():
            data = self.stream.data()
            _data = next(data)
            while True:
                try:
                    (msg, _data) = self.serializer.deserialize_msg(_data)
                except (HeaderTooShortError, PayloadTooShortError) as err:
                    logging.debug(f"{stream_id}: {err}")
                    try:
                        _data += next(data)
                    except StopIteration:
                        break
                except ProtocolError as err:
                    logging.debug(f"{stream_id}: {err}")
                    try:
                        _data = next(data)
                    except StopIteration:
                        break
                else:
                    src = (stream_id[0], stream_id[1])
                    dst = (stream_id[2], stream_id[3])
                    node = src
                    tor_proxy = None
                    if src in self.tor_proxies:
                        # dst port will be used to restore .onion node.
                        node = dst
                        tor_proxy = src
                    self.cache_message(
                        node, self.stream.timestamp, msg, tor_proxy=tor_proxy
                    )

    def cache_message(self, node, timestamp, msg, tor_proxy=None):
        """
        Subclass to implement method to cache message from the specified node.
        """
        raise NotImplementedError()


def get_pcap_file(pcap_dir, pcap_suffix):
    """
    Return the oldest available pcap file for processing.
    """
    try:
        oldest = min(glob.iglob(f"{pcap_dir}/*.{pcap_suffix}"))
    except ValueError as err:
        logging.error(err)
        return None

    try:
        latest = max(glob.iglob(f"{pcap_dir}/*.{pcap_suffix}"))
    except ValueError as err:
        logging.error(err)
        return None

    if oldest == latest:
        return None

    tmp = oldest
    dump = tmp.replace(f".{pcap_suffix}", f".{pcap_suffix}_")
    try:
        os.rename(tmp, dump)  # Mark file as being read.
    except OSError as err:
        logging.error(err)
        return None

    return dump
