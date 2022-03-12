#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# cache_inv.py - Saves inv messages from pcap files in Redis.
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
Saves inv messages from pcap files in Redis.
"""

import bisect
import hashlib
import logging
import os
import random
import sys
import time
from binascii import unhexlify
from collections import defaultdict
from ConfigParser import ConfigParser

from pcap import Cache, get_pcap_file
from utils import new_redis_conn

CONF = {}


class CacheInv(Cache):
    """
    Implements caching mechanic to cache messages from pcap file in Redis.
    """
    def __init__(self, *args, **kwargs):
        super(CacheInv, self).__init__(*args, **kwargs)
        self.count = 0
        self.ping_keys = set()  # ping:ADDRESS-PORT:NONCE
        self.invs = defaultdict(list)

    def cache_messages(self):
        """
        Reconstructs messages from TCP streams and caches them in Redis.
        """
        super(CacheInv, self).cache_messages()
        self.redis_pipe.execute()
        self.cache_rtt()
        self.redis_pipe.execute()

    def cache_message(self, node, timestamp, msg, is_tor=False):
        """
        Caches inv/pong message from the specified node.
        """
        if msg['command'] not in ("inv", "pong"):
            return

        # Restore .onion node using port info from node
        if is_tor:
            onion_node = self.redis_conn.get("onion:{}".format(node[1]))
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
                    rkey_ms = self.redis_conn.get(rkey)
                    if rkey_ms is None:
                        self.redis_conn.set(rkey, timestamp)
                        self.redis_pipe.set("lastblockhash", inv['hash'])
                    elif (timestamp - int(rkey_ms)) / 1000 > CONF['ttl']:
                        # Ignore block inv first seen more than 3 hours ago
                        logging.debug("Skip: %s (%d)", key, timestamp)
                        continue
                invs += 1
                # ZADD <key> LT <score> <member>
                # LT: Only update existing elements if the new score is less
                # than the current score. This flag doesn't prevent adding new
                # elements.
                self.redis_pipe.execute_command(
                    'ZADD', key, 'LT', timestamp, self.node_hash(node))
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
            timestamps = self.redis_conn.lrange(key, 0, 1)
            if len(timestamps) > 1:
                rtt_key = "rtt:{}".format(':'.join(key.split(":")[1:-1]))
                rtt = int(timestamps[1]) - int(timestamps[0])  # pong - ping
                logging.debug("%s: %d", rtt_key, rtt)
                self.redis_pipe.lpush(rtt_key, rtt)
                self.redis_pipe.ltrim(rtt_key, 0, CONF['rtt_count'] - 1)
                self.redis_pipe.expire(rtt_key, CONF['ttl'])


def cron():
    """
    Periodically fetches oldest pcap file to extract messages from.
    """
    redis_conn = new_redis_conn(db=CONF['db'])

    while True:
        time.sleep(random.randint(1, 50) / 100.0)  # 10 to 500ms

        dump = get_pcap_file(CONF['pcap_dir'], CONF['pcap_suffix'])
        if dump is None:
            continue

        if 0 in random.sample(range(0, 100), CONF['sampling_rate']):
            logging.debug("Loading: %s", dump)

            cache = CacheInv(
                dump,
                magic_number=CONF['magic_number'],
                tor_proxies=CONF['tor_proxies'],
                redis_conn=redis_conn)
            cache.cache_messages()

            logging.info("Dump: %s (%d entries)", dump, cache.count)
        else:
            logging.debug("Dropped: %s", dump)

        if not CONF['persist_pcap']:
            os.remove(dump)


def init_conf(config):
    """
    Populates CONF with key-value pairs from configuration file.
    """
    conf = ConfigParser()
    conf.read(config)
    CONF['logfile'] = conf.get('cache_inv', 'logfile')
    CONF['magic_number'] = unhexlify(conf.get('cache_inv', 'magic_number'))
    CONF['db'] = conf.getint('cache_inv', 'db')
    CONF['debug'] = conf.getboolean('cache_inv', 'debug')
    CONF['ttl'] = conf.getint('cache_inv', 'ttl')
    CONF['rtt_count'] = conf.getint('cache_inv', 'rtt_count')
    CONF['inv_count'] = conf.getint('cache_inv', 'inv_count')

    tor_proxies = conf.get('cache_inv', 'tor_proxies').strip().split("\n")
    CONF['tor_proxies'] = [
        (p.split(":")[0], int(p.split(":")[1])) for p in tor_proxies]

    CONF['pcap_dir'] = conf.get('cache_inv', 'pcap_dir')
    if not os.path.exists(CONF['pcap_dir']):
        os.makedirs(CONF['pcap_dir'])
    CONF['pcap_suffix'] = conf.get('cache_inv', 'pcap_suffix')

    CONF['persist_pcap'] = conf.getboolean('cache_inv', 'persist_pcap')
    CONF['sampling_rate'] = conf.getint('cache_inv', 'sampling_rate')


def main(argv):
    if len(argv) < 2 or not os.path.exists(argv[1]):
        print("Usage: cache_inv.py [config]")
        return 1

    # Initialize global conf
    init_conf(argv[1])

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

    cron()

    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
