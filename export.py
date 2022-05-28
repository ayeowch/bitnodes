#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# export.py - Exports enumerated data for reachable nodes into a JSON file.
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
Exports enumerated data for reachable nodes into a JSON file.
"""

import json
import logging
import os
import requests
import sys
import time
from binascii import hexlify, unhexlify
from collections import Counter
from ConfigParser import ConfigParser

from utils import new_redis_conn

REDIS_CONN = None
CONF = {}


class Export(object):
    """
    Exports nodes into timestamp-prefixed JSON file and sets consensus height
    using the most common height from these nodes.
    """
    def __init__(self, timestamp, nodes):
        self.start_t = time.time()
        self.timestamp = timestamp
        self.nodes = nodes
        self.heights = self.get_heights()

    def export_nodes(self):
        """
        Merges enumerated data for the nodes and exports them into
        timestamp-prefixed JSON file and then sets consensus height in Redis
        using the most common height from these nodes.
        """
        rows = []
        for node in self.nodes:
            row = self.get_row(node)
            rows.append(row)

        if self.heights:
            height = Counter(self.heights.values()).most_common(1)[0][0]
            logging.info("Consensus height: %s", height)
            REDIS_CONN.set('height', height)

        dump = os.path.join(
            CONF['export_dir'], "{}.json".format(self.timestamp))
        open(dump, 'w').write(json.dumps(rows, encoding="latin-1"))
        logging.info("Wrote %s", dump)

        logging.info("Elapsed: %d", time.time() - self.start_t)

    def get_row(self, node):
        """
        Returns enumerated row data from Redis for the specified node.
        """
        # address, port, version, user_agent, timestamp, services
        node = eval(node)
        address = node[0]
        port = node[1]
        services = node[-1]

        n = '{}-{}'.format(address, port)
        if n in self.heights:
            # Height from received block inv message in ping.py.
            height = (self.heights[n],)
        else:
            # Height from handshake in crawl.py.
            height = REDIS_CONN.get(
                'height:{}-{}-{}'.format(address, port, services))
            if height is None:
                height = (0,)
            else:
                height = (int(height),)
            logging.debug("Using handshake height %s: %s", node, height)

        hostname = REDIS_CONN.hget('resolve:{}'.format(address), 'hostname')
        hostname = (hostname,)

        geoip = REDIS_CONN.hget('resolve:{}'.format(address), 'geoip')
        if geoip is None:
            # city, country, latitude, longitude, timezone, asn, org
            geoip = (None, None, 0.0, 0.0, None, None, None)
        else:
            geoip = eval(geoip)

        return node + height + hostname + geoip

    def get_heights(self):
        """
        Returns the latest heights based on received block inv messages.
        """
        heights = {}
        recent_blocks = []
        timestamp_ms = self.timestamp * 1000

        try:
            response = requests.get(CONF['block_heights_url'], timeout=15)
        except requests.exceptions.RequestException as err:
            logging.warning(err)
        else:
            if response.status_code == 200:
                recent_blocks = response.json()['blocks']

        for block in recent_blocks:
            block_height, block_time, block_hash = block
            if block_time > self.timestamp:
                continue

            key = "binv:{}".format(block_hash)
            # [('ADDRESS-PORT', EPOCH_MS),..]
            nodes = REDIS_CONN.zrangebyscore(
                key, '-inf', '+inf', withscores=True, score_cast_func=int)
            for node in nodes:
                n, t = node
                if n not in heights and t <= timestamp_ms:
                    heights[n] = block_height

        logging.info("Heights: %d", len(heights))
        return heights


def init_conf(argv):
    """
    Populates CONF with key-value pairs from configuration file.
    """
    conf = ConfigParser()
    conf.read(argv[1])
    CONF['logfile'] = conf.get('export', 'logfile')
    CONF['magic_number'] = unhexlify(conf.get('export', 'magic_number'))
    CONF['db'] = conf.getint('export', 'db')
    CONF['debug'] = conf.getboolean('export', 'debug')
    CONF['export_dir'] = conf.get('export', 'export_dir')
    CONF['block_heights_url'] = conf.get('export', 'block_heights_url')
    if not os.path.exists(CONF['export_dir']):
        os.makedirs(CONF['export_dir'])


def main(argv):
    if len(argv) < 2 or not os.path.exists(argv[1]):
        print("Usage: export.py [config]")
        return 1

    # Initialize global conf
    init_conf(argv)

    # Initialize logger
    loglevel = logging.INFO
    if CONF['debug']:
        loglevel = logging.DEBUG

    logformat = ("%(asctime)s,%(msecs)05.1f %(levelname)s (%(funcName)s) "
                 "%(message)s")
    logging.basicConfig(level=loglevel,
                        format=logformat,
                        filename=CONF['logfile'],
                        filemode='w')
    print("Log: {}, press CTRL+C to terminate..".format(CONF['logfile']))

    global REDIS_CONN
    REDIS_CONN = new_redis_conn(db=CONF['db'])

    subscribe_key = 'resolve:{}'.format(hexlify(CONF['magic_number']))
    publish_key = 'export:{}'.format(hexlify(CONF['magic_number']))

    pubsub = REDIS_CONN.pubsub()
    pubsub.subscribe(subscribe_key)
    while True:
        msg = pubsub.get_message()
        if msg is None:
            time.sleep(0.1)  # 100 ms artificial intrinsic latency.
            continue
        # 'resolve' message is published by resolve.py after resolving hostname
        # and GeoIP data for all reachable nodes.
        if msg['channel'] == subscribe_key and msg['type'] == 'message':
            timestamp = int(msg['data'])  # From ping.py's 'snapshot' message
            logging.info("Timestamp: %d", timestamp)
            nodes = REDIS_CONN.smembers('opendata')
            logging.info("Nodes: %d", len(nodes))
            export = Export(timestamp, nodes)
            export.export_nodes()
            REDIS_CONN.publish(publish_key, timestamp)

    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
