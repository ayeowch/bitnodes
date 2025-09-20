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
from functools import cache

import mmh3
from binascii import unhexlify

from pcap import Cache, get_pcap_file, remove_pcap_file
from utils import (
    conf_list,
    http_get_txt,
    init_logger,
    ip_port_list,
    new_redis_conn,
    throttle_run,
    txt_items,
)

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

    @staticmethod
    @cache
    def node_key(node):
        """
        Encode a tuple of address and port in shorten key for storage in Redis.
        """
        return mmh3.mmh3_x64_128_digest(f"{node[0]}-{node[1]}".encode()).hex()[:16]

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
                self.cache_inv(
                    node,
                    timestamp,
                    inv["type"],
                    inv["hash"].decode(),
                )

        elif msg["command"] == b"pong":
            self.cache_pong(node, timestamp, msg["nonce"])

        if len(self.redis_pipe) >= 5000:
            self.redis_pipe.execute()

    def is_accepted_inv(self, key, type, timestamp):
        """
        Accept inv key based on the set rules.
        """
        # Deterministically accept inv key at the specified sampling rate.
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

    def cache_inv(self, node, timestamp, type, hash):
        """
        Cache inv message from the specified node.
        """
        if type not in (1, 2):
            return

        if type == 2 and hash[-16:] in CONF["blockhash_suffixes"]:
            return

        if type == 1:
            # Keyed by hourly bucket indexed from 0 to 9.
            bucket = (int(timestamp / 1000) // 3600) % 10
            key = f"inv:{type}:{bucket}:{hash}"
        else:
            key = f"inv:{type}:{hash}"

        if not self.is_accepted_inv(key, type, timestamp):
            logging.debug("Skip: %s (%d)", key, timestamp)
            return

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
                logging.debug("Skip: %s (%d)", key, timestamp)
                return

        # ZADD <key> LT <score> <member>
        # LT: Only update existing elements if the new score is less
        # than the current score. This flag doesn't prevent adding new
        # elements.
        self.redis_pipe.execute_command(
            "ZADD", key, "LT", timestamp, self.node_key(node)
        )

        # Set expiry for block invs.
        # Removal of transaction invs should be managed separately, e.g. using
        # hourly job to remove transaction invs from old buckets.
        if type == 2:
            self.redis_pipe.expire(key, CONF["ttl"])

    def cache_pong(self, node, timestamp, nonce):
        """
        Cache pong message from the specified node.
        """
        key = f"ping:{node[0]}-{node[1]}:{nonce}"
        self.redis_pipe.rpushx(key, timestamp)
        self.ping_keys.add(key)

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
                logging.debug("%s: %d", rtt_key, rtt)
                self.redis_pipe.lpush(rtt_key, rtt)
                self.redis_pipe.ltrim(rtt_key, 0, CONF["rtt_count"] - 1)
                self.redis_pipe.expire(rtt_key, CONF["ttl"])


def cron():
    """
    Periodically fetch oldest pcap file to extract messages from.
    """
    redis_conn = new_redis_conn(db=CONF["db"])

    while True:
        time.sleep(random.randint(50, 500) / 1000)  # 50 to 500ms.

        dump = get_pcap_file(CONF["pcap_dir"], CONF["pcap_suffix"])
        if dump is None:
            continue

        if random.randint(1, 100) <= CONF["pcap_sampling_rate"]:
            logging.debug("Loading: %s", dump)

            update_excluded_src_addrs(redis_conn)

            cache = CacheInv(
                dump,
                magic_number=CONF["magic_number"],
                exclude_src_addrs=CONF["current_exclude_src_addrs"],
                tor_proxies=CONF["tor_proxies"],
                redis_conn=redis_conn,
            )
            start_t = time.monotonic()
            cache.cache_messages()
            elapsed = time.monotonic() - start_t
            logging.info(
                "%s (pkt=%d tx=%d block=%d pong=%d s=%.2f)",
                dump.split("/")[-1],
                cache.tcp_pkts,
                len(cache.invs[1]),
                len(cache.invs[2]),
                len(cache.ping_keys),
                elapsed,
            )
        else:
            logging.debug("Dropped: %s", dump)

        if not CONF["persist_pcap"]:
            remove_pcap_file(dump)


def load_blockhash_suffixes(filepath):
    """
    Load old block hashes in 16-char suffixes from a JSON file.
    """
    suffixes = set()
    if os.path.exists(filepath):
        with open(filepath) as json_file:
            suffixes.update(set(json.load(json_file)))
    return suffixes


def set_excluded_src_addrs(redis_conn):
    """
    Set latest excluded source addrs from Redis in CONF.
    """
    addrs = redis_conn.get("exclude-src-addrs")
    if addrs is not None:
        CONF["current_exclude_src_addrs"] = {tuple(item) for item in json.loads(addrs)}


@throttle_run(ttl=300)
def update_excluded_src_addrs(redis_conn):
    """
    Update excluded source addrs and store them Redis.
    """
    exclude_src_addrs = set()

    if CONF["exclude_src_addrs"]:
        exclude_src_addrs.update(CONF["exclude_src_addrs"])

    if CONF["exclude_src_addrs_from_url"]:
        txt = http_get_txt(CONF["exclude_src_addrs_from_url"])
        exclude_src_addrs.update(set(ip_port_list(txt_items(txt))))

    logging.debug("Addrs: %d", len(exclude_src_addrs))
    redis_conn.set("exclude-src-addrs", json.dumps(list(exclude_src_addrs)))
    set_excluded_src_addrs(redis_conn)


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
    CONF["tor_proxies"] = set(ip_port_list(conf_list(conf, "cache_inv", "tor_proxies")))

    CONF["pcap_dir"] = conf.get("cache_inv", "pcap_dir")
    if not os.path.exists(CONF["pcap_dir"]):
        os.makedirs(CONF["pcap_dir"])
    CONF["pcap_suffix"] = conf.get("cache_inv", "pcap_suffix")

    CONF["persist_pcap"] = conf.getboolean("cache_inv", "persist_pcap")
    CONF["pcap_sampling_rate"] = conf.getint("cache_inv", "pcap_sampling_rate")

    CONF["blockhash_suffixes"] = load_blockhash_suffixes(
        conf.get("cache_inv", "blockhash_suffixes")
    )

    CONF["exclude_src_addrs"] = set(
        ip_port_list(conf_list(conf, "cache_inv", "exclude_src_addrs"))
    )
    CONF["exclude_src_addrs_from_url"] = conf.get(
        "cache_inv", "exclude_src_addrs_from_url"
    )
    CONF["current_exclude_src_addrs"] = set()


def main(argv):
    if len(argv) < 2 or not os.path.exists(argv[1]):
        print("Usage: cache_inv.py [config]")
        return 1

    # Initialize global conf.
    init_conf(argv[1])

    # Initialize logger.
    init_logger(CONF["logfile"], debug=CONF["debug"], filemode="a")

    cron()

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
