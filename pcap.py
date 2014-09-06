#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# pcap.py - Saves inv messages from pcap files in Redis.
#
# Copyright (c) 2014 Addy Yeow Chin Heng <ayeowch@gmail.com>
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
Saves inv messages from pcap files in Redis.
"""

import dpkt
import glob
import logging
import os
import redis
import socket
import sys
import time
from ConfigParser import ConfigParser

from protocol import ProtocolError, Serializer

# Redis connection setup
REDIS_SOCKET = os.environ.get('REDIS_SOCKET', "/tmp/redis.sock")
REDIS_PASSWORD = os.environ.get('REDIS_PASSWORD', None)
REDIS_CONN = redis.StrictRedis(unix_socket_path=REDIS_SOCKET,
                               password=REDIS_PASSWORD)

SETTINGS = {}


def save_invs(timestamp, node, invs):
    """
    Adds inv messages into the inv set in Redis. Block inv messages for block
    older than the configured TTL are ignored.
    """
    timestamp = int(timestamp * 1000)  # in ms
    redis_pipe = REDIS_CONN.pipeline()
    for inv in invs:
        key = "inv:{}:{}".format(inv['type'], inv['hash'])

        if inv['type'] == 2:
            # Redis key for reference (first seen) block inv
            rkey = "r{}".format(key)
            rkey_timestamp = REDIS_CONN.get(rkey)
            if rkey_timestamp is None:
                REDIS_CONN.set(rkey, timestamp)
            elif (timestamp - int(rkey_timestamp)) / 1000 > SETTINGS['ttl']:
                # Ignore block inv if it was first seen more than 3 hours ago
                logging.debug("Drop: {}:{}".format(inv['type'], inv['hash']))
                continue

        logging.debug("[{}] {}:{}".format(timestamp, inv['type'], inv['hash']))
        redis_pipe.zadd(key, timestamp, node)
        redis_pipe.expire(key, SETTINGS['ttl'])
    redis_pipe.execute()


def get_invs(filepath):
    """
    Extracts inv messages from the specified pcap file.
    """
    count = 0
    serializer = Serializer()
    pcap_file = open(filepath)
    pcap_reader = dpkt.pcap.Reader(pcap_file)
    for timestamp, buf in pcap_reader:
        frame = dpkt.ethernet.Ethernet(buf)
        ip_packet = frame.data
        if isinstance(ip_packet.data, dpkt.tcp.TCP):
            tcp_packet = ip_packet.data
            payload = tcp_packet.data
            if len(payload) > 0:
                try:
                    (msg, _) = serializer.deserialize_msg(payload)
                except ProtocolError:
                    pass
                else:
                    if msg['command'] == "inv":
                        if ip_packet.v == 6:
                            address = socket.inet_ntop(socket.AF_INET6,
                                                       ip_packet.src)
                        else:
                            address = socket.inet_ntop(socket.AF_INET,
                                                       ip_packet.src)
                        node = (address, tcp_packet.sport)
                        save_invs(timestamp, node, msg['inventory'])
                        count += msg['count']
    pcap_file.close()
    return count


def cron():
    """
    Periodically fetches oldest pcap file to extract inv messages from.
    """
    while True:
        time.sleep(5)

        try:
            oldest = min(glob.iglob("{}/*.pcap".format(SETTINGS['pcap_dir'])))
        except ValueError as err:
            logging.warning(err)
            continue
        latest = max(glob.iglob("{}/*.pcap".format(SETTINGS['pcap_dir'])))
        if oldest == latest:
            continue
        tmp = oldest
        dump = tmp.replace(".pcap", ".pcap_")
        try:
            os.rename(tmp, dump)  # Mark file as being read
        except OSError as err:
            logging.warning(err)
            continue

        start = time.time()
        count = get_invs(dump)
        end = time.time()
        elapsed = end - start

        logging.info("Dump:{} ({} invs)".format(dump, count))
        logging.info("Elapsed: {}".format(elapsed))

        os.remove(dump)


def init_settings(argv):
    """
    Populates SETTINGS with key-value pairs from configuration file.
    """
    conf = ConfigParser()
    conf.read(argv[1])
    SETTINGS['logfile'] = conf.get('pcap', 'logfile')
    SETTINGS['debug'] = conf.getboolean('pcap', 'debug')
    SETTINGS['ttl'] = conf.getint('pcap', 'ttl')
    SETTINGS['pcap_dir'] = conf.get('pcap', 'pcap_dir')
    if not os.path.exists(SETTINGS['pcap_dir']):
        os.makedirs(SETTINGS['pcap_dir'])


def main(argv):
    if len(argv) < 2 or not os.path.exists(argv[1]):
        print("Usage: pcap.py [config]")
        return 1

    # Initialize global settings
    init_settings(argv)

    # Initialize logger
    loglevel = logging.INFO
    if SETTINGS['debug']:
        loglevel = logging.DEBUG

    logformat = ("%(asctime)s,%(msecs)05.1f %(levelname)s (%(funcName)s) "
                 "%(message)s")
    logging.basicConfig(level=loglevel,
                        format=logformat,
                        filename=SETTINGS['logfile'],
                        filemode='a')
    print("Writing output to {}, press CTRL+C to terminate..".format(
          SETTINGS['logfile']))

    cron()

    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
