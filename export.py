#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# export.py - Exports enumerated data for reachable nodes into a JSON file.
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
Exports enumerated data for reachable nodes into a JSON file.
"""

import json
import logging
import os
import sys
import time
from collections import Counter
from configparser import ConfigParser

from binascii import hexlify, unhexlify

from resolve import Resolve
from utils import http_get, new_redis_conn

CONF = {}


class Export(object):
    """
    Exports nodes into timestamp-prefixed JSON file and sets consensus height
    using the most common height from these nodes.
    """

    def __init__(self, timestamp=None, nodes=None, redis_conn=None):
        self.start_t = time.time()
        self.timestamp = timestamp
        self.nodes = nodes
        self.redis_conn = redis_conn
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
            if row[-2] is None:
                logging.warning(f"Skipping {row[0]} due to missing ASN")
                continue
            rows.append(row)

        if self.heights:
            height = Counter(self.heights.values()).most_common(1)[0][0]
            logging.info(f"Consensus height: {height}")
            self.redis_conn.set("height", height)

        self.write_json_file(rows)

        logging.info(f"Elapsed: {time.time() - self.start_t}")

    def write_json_file(self, rows):
        """
        Writes rows into timestamp-prefixed JSON file.
        """
        json_file = os.path.join(CONF["export_dir"], f"{self.timestamp}.json")
        open(json_file, "w").write(json.dumps(rows))
        logging.info(f"Wrote {json_file}")

    def get_row(self, node):
        """
        Returns enumerated row data from Redis for the specified node.
        """
        # address, port, version, user_agent, timestamp, services
        node = eval(node)
        address = node[0]
        port = node[1]
        services = node[-1]

        n = f"{address}-{port}"
        if n in self.heights:
            # Height from received block inv message in ping.py.
            height = (self.heights[n],)
        else:
            # Height from handshake in crawl.py.
            height = self.redis_conn.get(f"height:{address}-{port}-{services}")
            if height is None:
                height = (0,)
            else:
                height = (int(height),)
            logging.debug(f"Using handshake height {node}: {height}")

        hostname = self.redis_conn.hget(f"resolve:{address}", "hostname")
        if hostname:
            hostname = hostname.decode()
        hostname = (hostname,)

        geoip = self.redis_conn.hget(f"resolve:{address}", "geoip")
        if geoip is None:
            # resolve.py may not have seen this node in opendata yet when
            # it last ran, so manually trigger raw geoip now.
            logging.warning(f"Raw geoip triggered for {address}")
            geoip = Resolve().raw_geoip(address)
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

        response = http_get(CONF["block_heights_url"])
        if response is not None:
            recent_blocks = response.json()["blocks"]

        for block in recent_blocks:
            block_height, block_time, block_hash = block
            if block_time > self.timestamp:
                continue

            key = f"binv:{block_hash}"
            # [('ADDRESS-PORT', EPOCH_MS),..]
            nodes = self.redis_conn.zrangebyscore(
                key, "-inf", "+inf", withscores=True, score_cast_func=int
            )
            for node in nodes:
                n, t = node
                n = n.decode()
                if n not in heights and t <= timestamp_ms:
                    heights[n] = block_height

        logging.info(f"Heights: {len(heights)}")
        return heights


def cron():
    """
    Subscribes to 'resolve' message from resolve.py to export GeoIP resolved
    nodes into a JSON file.
    """
    redis_conn = new_redis_conn(db=CONF["db"])

    magic_number = hexlify(CONF["magic_number"]).decode()
    subscribe_key = f"resolve:{magic_number}"
    publish_key = f"export:{magic_number}"

    pubsub = redis_conn.pubsub()
    pubsub.subscribe(subscribe_key)

    while True:
        msg = pubsub.get_message()
        if msg is None:
            time.sleep(0.1)  # 100 ms artificial intrinsic latency.
            continue

        channel = msg["channel"].decode()

        # 'resolve' message is published by resolve.py after resolving hostname
        # and GeoIP data for all reachable nodes.
        if channel == subscribe_key and msg["type"] == "message":
            timestamp = int(msg["data"])  # From ping.py's 'snapshot' message.
            logging.info(f"Timestamp: {timestamp}")

            nodes = redis_conn.smembers("opendata")
            logging.info(f"Nodes: {len(nodes)}")

            export = Export(timestamp=timestamp, nodes=nodes, redis_conn=redis_conn)
            export.export_nodes()

            redis_conn.publish(publish_key, timestamp)


def init_conf(config):
    """
    Populates CONF with key-value pairs from configuration file.
    """
    conf = ConfigParser()
    conf.read(config)
    CONF["logfile"] = conf.get("export", "logfile")
    CONF["magic_number"] = unhexlify(conf.get("export", "magic_number"))
    CONF["db"] = conf.getint("export", "db")
    CONF["debug"] = conf.getboolean("export", "debug")
    CONF["export_dir"] = conf.get("export", "export_dir")
    CONF["block_heights_url"] = conf.get("export", "block_heights_url")
    if not os.path.exists(CONF["export_dir"]):
        os.makedirs(CONF["export_dir"])


def main(argv):
    if len(argv) < 2 or not os.path.exists(argv[1]):
        print("Usage: export.py [config]")
        return 1

    # Initialize global conf.
    init_conf(argv[1])

    # Initialize logger.
    loglevel = logging.INFO
    if CONF["debug"]:
        loglevel = logging.DEBUG

    logformat = (
        "[%(process)d] %(asctime)s,%(msecs)05.1f %(levelname)s "
        "(%(funcName)s) %(message)s"
    )
    logging.basicConfig(
        level=loglevel, format=logformat, filename=CONF["logfile"], filemode="w"
    )
    print(f"Log: {CONF['logfile']}, press CTRL+C to terminate..")

    cron()

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
