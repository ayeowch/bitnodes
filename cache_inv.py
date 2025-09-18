#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# cache_inv.py - Save inv messages from pcap files in Redis.
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
Save inv messages from pcap files in Redis.
"""

import bisect
import json
import logging
import os
import random
import sys
import time
from collections import defaultdict
from configparser import ConfigParser

import mmh3
from binascii import unhexlify

from pcap import Cache, get_pcap_file
from utils import new_redis_conn

CONF = {}


class CacheInv(Cache):
    """
    Implement caching mechanic to cache messages from pcap file in Redis.
    """

    def __init__(self, *args, **kwargs):
        super(CacheInv, self).__init__(*args, **kwargs)
        self.ping_keys = set()  # ping:ADDRESS-PORT:NONCE
        self.invs = {
            1: defaultdict(list),  # Transaction invs.
            2: defaultdict(list),  # Block invs.
        }

    def cache_messages(self):
        """
        Reconstruct messages from TCP streams and caches them in Redis.
        """
        super(CacheInv, self).cache_messages()
        self.redis_pipe.execute()
        self.cache_rtt()
        self.redis_pipe.execute()

    def cache_message(self, node, timestamp, msg, tor_proxy=None):
        """
        Cache inv/pong message from the specified node.
        """
        if msg["command"] not in (b"inv", b"pong"):
            return

        # Restore .onion node using port info from node.
        if tor_proxy:
            onion_node = self.redis_conn.get(f"onion:{node[1]}:{tor_proxy[1]}")
            if onion_node is None:
                return
            node = json.loads(onion_node)

        if msg["command"] == b"inv":
            if tor_proxy and not CONF["onion"]:
                return  # Not caching invs from .onion node.

            for inv in msg["inventory"]:
                type = inv["type"]
                hash = inv["hash"].decode()
                if type not in (1, 2):
                    continue
                if type == 2 and hash[-16:] in CONF["blockhash_suffixes"]:
                    continue
                key = f"inv:{type}:{hash}"
                if not self.is_accepted_inv(key, type, timestamp):
                    logging.debug(f"Skip: {key} ({timestamp})")
                    continue
                bisect.insort(self.invs[type][key], timestamp)
                if type == 2:
                    # Redis key for reference (first seen) block inv.
                    rkey = f"r{key}"
                    rkey_ms = self.redis_conn.get(rkey)
                    if rkey_ms is None:
                        self.redis_conn.set(rkey, timestamp)
                        self.redis_pipe.set("lastblockhash", hash)
                    elif (timestamp - int(rkey_ms)) / 1000 > CONF["ttl"]:
                        # Ignore block inv first seen more than 3 hours ago
                        logging.debug(f"Skip: {key} ({timestamp})")
                        continue
                # ZADD <key> LT <score> <member>
                # LT: Only update existing elements if the new score is less
                # than the current score. This flag doesn't prevent adding new
                # elements.
                self.redis_pipe.execute_command(
                    "ZADD", key, "LT", timestamp, self.node_key(node)
                )
                self.redis_pipe.expire(key, CONF["ttl"])
        elif msg["command"] == b"pong":
            key = f"ping:{node[0]}-{node[1]}:{msg['nonce']}"
            self.redis_pipe.rpushx(key, timestamp)
            self.ping_keys.add(key)

    def is_accepted_inv(self, key, type, timestamp):
        """
        Accept inv key based on the set rules.
        """
        # Deterministically accepts inv key at the specified sampling rate.
        if hash(key) % 100 >= CONF[f"inv_{type}_sampling_rate"]:
            return False

        # Skip inv key if there are already enough timestamps associated to it
        # unless if the timestamp is older than the earliest stored timestamp.
        if (
            len(self.invs[type][key]) >= CONF[f"inv_{type}_count"]
            and timestamp > self.invs[type][key][0]
        ):
            return False

        return True

    def node_key(self, node):
        """
        Encode a tuple of address and port in shorten key for storage in Redis.
        """
        return mmh3.mmh3_x64_128_digest(f"{node[0]}-{node[1]}".encode()).hex()[:16]

    def cache_rtt(self):
        """
        Calculate round-trip time (RTT) values and cache them in Redis.
        """
        for key in self.ping_keys:
            timestamps = self.redis_conn.lrange(key, 0, 1)
            if len(timestamps) > 1:
                node = ":".join(key.split(":")[1:-1])
                rtt_key = f"rtt:{node}"
                rtt = int(timestamps[1]) - int(timestamps[0])  # pong - ping
                logging.debug(f"{rtt_key}: {rtt}")
                self.redis_pipe.lpush(rtt_key, rtt)
                self.redis_pipe.ltrim(rtt_key, 0, CONF["rtt_count"] - 1)
                self.redis_pipe.expire(rtt_key, CONF["ttl"])


def cron():
    """
    Periodically fetch oldest pcap file to extract messages from.
    """
    redis_conn = new_redis_conn(db=CONF["db"])

    while True:
        time.sleep(random.randint(1, 50) / 100.0)  # 10 to 500ms

        dump = get_pcap_file(CONF["pcap_dir"], CONF["pcap_suffix"])
        if dump is None:
            continue

        if random.randint(1, 100) <= CONF["pcap_sampling_rate"]:
            logging.debug(f"Loading: {dump}")

            cache = CacheInv(
                dump,
                magic_number=CONF["magic_number"],
                tor_proxies=CONF["tor_proxies"],
                redis_conn=redis_conn,
            )
            cache.cache_messages()

            logging.info(
                f"Dump: {dump} " f"(tx={len(cache.invs[1])} block={len(cache.invs[2])})"
            )
        else:
            logging.debug(f"Dropped: {dump}")

        if not CONF["persist_pcap"]:
            os.remove(dump)


def load_blockhash_suffixes(filepath):
    """
    Load old block hashes in 16-char suffixes from a JSON file.
    """
    suffixes = set()
    if os.path.exists(filepath):
        with open(filepath) as json_file:
            suffixes.update(set(json.load(json_file)))
    return suffixes


def init_conf(config):
    """
    Populate CONF with key-value pairs from configuration file.
    """
    conf = ConfigParser()
    conf.read(config)
    CONF["logfile"] = conf.get("cache_inv", "logfile")
    CONF["magic_number"] = unhexlify(conf.get("cache_inv", "magic_number"))
    CONF["db"] = conf.getint("cache_inv", "db")
    CONF["debug"] = conf.getboolean("cache_inv", "debug")
    CONF["ttl"] = conf.getint("cache_inv", "ttl")
    CONF["rtt_count"] = conf.getint("cache_inv", "rtt_count")
    CONF["inv_1_count"] = conf.getint("cache_inv", "inv_1_count")
    CONF["inv_2_count"] = conf.getint("cache_inv", "inv_2_count")
    CONF["inv_1_sampling_rate"] = conf.getint("cache_inv", "inv_1_sampling_rate")
    CONF["inv_2_sampling_rate"] = conf.getint("cache_inv", "inv_2_sampling_rate")

    CONF["onion"] = conf.getboolean("cache_inv", "onion")
    tor_proxies = conf.get("cache_inv", "tor_proxies").strip().split("\n")
    CONF["tor_proxies"] = set(
        [(p.split(":")[0], int(p.split(":")[1])) for p in tor_proxies]
    )

    CONF["pcap_dir"] = conf.get("cache_inv", "pcap_dir")
    if not os.path.exists(CONF["pcap_dir"]):
        os.makedirs(CONF["pcap_dir"])
    CONF["pcap_suffix"] = conf.get("cache_inv", "pcap_suffix")

    CONF["persist_pcap"] = conf.getboolean("cache_inv", "persist_pcap")
    CONF["pcap_sampling_rate"] = conf.getint("cache_inv", "pcap_sampling_rate")

    CONF["blockhash_suffixes"] = load_blockhash_suffixes(
        conf.get("cache_inv", "blockhash_suffixes")
    )


def main(argv):
    if len(argv) < 2 or not os.path.exists(argv[1]):
        print("Usage: cache_inv.py [config]")
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
        level=loglevel, format=logformat, filename=CONF["logfile"], filemode="a"
    )
    print(f"Log: {CONF['logfile']}, press CTRL+C to terminate..")

    cron()

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
