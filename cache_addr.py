#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# cache_addr.py - Saves addr messages from pcap files in Redis.
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
Saves addr messages from pcap files in Redis.
"""

import logging
import os
import random
import sys
import time
from binascii import unhexlify
from ConfigParser import ConfigParser
from ipaddress import ip_address

from pcap import Cache, get_pcap_file
from protocol import (
    NETWORK_IPV4,
    NETWORK_IPV6,
    NETWORK_TORV2,
    NETWORK_TORV3,
)
from utils import get_keys, new_redis_conn

CONF = {}


class AddrManager(object):
    """
    Manages addr entries in Redis.
    """
    def __init__(self, redis_conn=None, redis_pipe=None):
        self.redis_conn = redis_conn
        self.redis_pipe = redis_pipe
        self.ipv4_key = 'addr:ipv4'
        self.ipv6_key = 'addr:ipv6'
        self.onion_key = 'addr:onion'
        self.now = int(time.time())

    def is_excluded(self, address):
        """
        Returns True to exclude private address.
        """
        if address.endswith(".onion"):
            return False

        if ip_address(unicode(address)).is_private:
            return True

        return False

    def add(self, from_node, addr):
        """
        Adds addr entry in Redis.
        """
        network_id = addr['network_id']
        timestamp = addr['timestamp']
        services = addr['services']
        port = addr['port']

        # Timestamp truncated to 30-minute interval
        t_bucket = timestamp - (timestamp % 1800)
        age = self.now - t_bucket
        if age < 0 or age > CONF['max_age']:
            return

        key = None
        if network_id == NETWORK_IPV4:
            addr = (addr['ipv4'], port, services)
            key = self.ipv4_key
        elif network_id == NETWORK_IPV6:
            addr = (addr['ipv6'], port, services)
            key = self.ipv6_key
        elif network_id in (NETWORK_TORV2, NETWORK_TORV3):
            addr = (addr['onion'], port, services)
            key = self.onion_key

        if key and not self.is_excluded(addr[0]):
            fkey = "{}:{}-{}".format(key, from_node[0], from_node[1])
            val = "{}-{}-{}".format(*addr)

            # ZADD <key> GT <score> <member>
            # GT: Only update existing elements if the new score is greater
            # than the current score. This flag doesn't prevent adding new
            # elements.
            self.redis_pipe.execute_command('ZADD', key, 'GT', t_bucket, val)
            self.redis_pipe.execute_command('ZADD', fkey, 'GT', t_bucket, val)

    def cleanup(self):
        """
        Removes old addr entries from Redis.
        """
        keys = (self.ipv4_key, self.ipv6_key, self.onion_key)
        max_score = self.now - CONF['expiry_age']
        for key in keys:
            removed = self.redis_conn.zremrangebyscore(key, 0, max_score)
            logging.info("Key: %s (%d removed)", key, removed)
            if removed > 0:
                for fkey in get_keys(self.redis_conn, '{}:*'.format(key)):
                    self.redis_pipe.zremrangebyscore(fkey, 0, max_score)


class CacheAddr(Cache):
    """
    Implements caching mechanic to cache messages from pcap file in Redis.
    """
    def __init__(self, *args, **kwargs):
        super(CacheAddr, self).__init__(*args, **kwargs)
        self.count = 0
        self.addr_manager = AddrManager(
            redis_conn=self.redis_conn, redis_pipe=self.redis_pipe)

    def cache_messages(self):
        """
        Reconstructs messages from TCP streams and caches them in Redis.
        """
        super(CacheAddr, self).cache_messages()
        self.redis_pipe.execute()

    def cache_message(self, node, timestamp, msg, **kwargs):
        """
        Caches addr message from the specified node.
        """
        if msg['command'] not in ("addr", "addrv2"):
            return

        addr_list = msg['addr_list'][:CONF['peers_per_node']]
        self.count += len(addr_list)
        for addr in addr_list:
            self.addr_manager.add(node, addr)


def cron():
    """
    Periodically fetches oldest pcap file to extract messages from.
    """
    redis_conn = new_redis_conn(db=CONF['db'])
    last_cleanup = 0

    while True:
        time.sleep(random.randint(1, 50) / 100.0)  # 10 to 500ms

        dump = get_pcap_file(CONF['pcap_dir'], CONF['pcap_suffix'])
        if dump is None:
            continue

        logging.debug("Loading: %s", dump)

        cache = CacheAddr(
            dump,
            magic_number=CONF['magic_number'],
            redis_conn=redis_conn)
        cache.cache_messages()

        logging.info("Dump: %s (%d entries)", dump, cache.count)

        if cache.addr_manager.now - last_cleanup > CONF['max_age']:
            cache.addr_manager.cleanup()
            last_cleanup = cache.addr_manager.now

        if not CONF['persist_pcap']:
            os.remove(dump)


def init_conf(config):
    """
    Populates CONF with key-value pairs from configuration file.
    """
    conf = ConfigParser()
    conf.read(config)
    CONF['logfile'] = conf.get('cache_addr', 'logfile')
    CONF['magic_number'] = unhexlify(conf.get('cache_addr', 'magic_number'))
    CONF['db'] = conf.getint('cache_addr', 'db')
    CONF['debug'] = conf.getboolean('cache_addr', 'debug')
    CONF['max_age'] = conf.getint('cache_addr', 'max_age')
    CONF['expiry_age'] = conf.getint('cache_addr', 'expiry_age')
    CONF['peers_per_node'] = conf.getint('cache_addr', 'peers_per_node')

    CONF['pcap_dir'] = conf.get('cache_addr', 'pcap_dir')
    if not os.path.exists(CONF['pcap_dir']):
        os.makedirs(CONF['pcap_dir'])
    CONF['pcap_suffix'] = conf.get('cache_addr', 'pcap_suffix')

    CONF['persist_pcap'] = conf.getboolean('cache_addr', 'persist_pcap')


def main(argv):
    if len(argv) < 2 or not os.path.exists(argv[1]):
        print("Usage: cache_addr.py [config]")
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
