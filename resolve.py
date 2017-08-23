#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# resolve.py - Resolves hostname and GeoIP data for each reachable node.
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
Resolves hostname and GeoIP data for each reachable node.
"""

from gevent import monkey
monkey.patch_all()

import gevent
import gevent.pool
import logging
import os
import pygeoip
import redis
import redis.connection
import socket
import sys
import time
from binascii import hexlify, unhexlify
from collections import defaultdict
from ConfigParser import ConfigParser
from decimal import Decimal

from utils import new_redis_conn

redis.connection.socket = gevent.socket

REDIS_CONN = None
CONF = {}

# MaxMind databases
GEOIP4 = pygeoip.GeoIP("geoip/GeoLiteCity.dat", pygeoip.MEMORY_CACHE)
GEOIP6 = pygeoip.GeoIP("geoip/GeoLiteCityv6.dat", pygeoip.MEMORY_CACHE)
ASN4 = pygeoip.GeoIP("geoip/GeoIPASNum.dat", pygeoip.MEMORY_CACHE)
ASN6 = pygeoip.GeoIP("geoip/GeoIPASNumv6.dat", pygeoip.MEMORY_CACHE)


class Resolve(object):
    """
    Implements hostname and GeoIP resolver.
    """
    def __init__(self, addresses):
        self.addresses = addresses
        self.resolved = defaultdict(dict)
        self.redis_pipe = REDIS_CONN.pipeline()

    def resolve_addresses(self):
        """
        Resolves hostname for up to 1000 new addresses and GeoIP data for all
        addresses.
        """
        start = time.time()

        idx = 0
        for address in self.addresses:
            key = 'resolve:{}'.format(address)

            ttl = REDIS_CONN.ttl(key)
            expiring = False
            if ttl < 0.1 * CONF['ttl']:  # Less than 10% of initial TTL
                expiring = True

            if expiring and idx < 1000 and not address.endswith(".onion"):
                self.resolved['hostname'][address] = None
                idx += 1

            self.resolved['geoip'][address] = None

        logging.info("GeoIP: %d", len(self.resolved['geoip']))
        self.resolve_geoip()

        logging.info("Hostname: %d", len(self.resolved['hostname']))
        self.resolve_hostname()

        self.cache_resolved()

        end = time.time()
        elapsed = end - start
        logging.info("Elapsed: %d", elapsed)

    def cache_resolved(self):
        """
        Caches resolved addresses in Redis.
        """
        resolved = 0
        for address, geoip in self.resolved['geoip'].iteritems():
            if geoip[1] or geoip[5]:
                resolved += 1  # country/asn is set
            key = 'resolve:{}'.format(address)
            self.redis_pipe.hset(key, 'geoip', geoip)
            logging.debug("%s geoip: %s", key, geoip)
        logging.info("GeoIP: %d resolved", resolved)

        resolved = 0
        for address, hostname in self.resolved['hostname'].iteritems():
            if hostname != address:
                resolved += 1
            key = 'resolve:{}'.format(address)
            self.redis_pipe.hset(key, 'hostname', hostname)
            self.redis_pipe.expire(key, CONF['ttl'])
            logging.debug("%s hostname: %s", key, hostname)
        logging.info("Hostname: %d resolved", resolved)

        self.redis_pipe.execute()

    def resolve_geoip(self):
        """
        Resolves GeoIP data for the unresolved addresses.
        """
        for address in self.resolved['geoip']:
            geoip = raw_geoip(address)
            self.resolved['geoip'][address] = geoip

    def resolve_hostname(self):
        """
        Concurrently resolves hostname for the unresolved addresses.
        """
        pool = gevent.pool.Pool(len(self.resolved['hostname']))
        with gevent.Timeout(15, False):
            for address in self.resolved['hostname']:
                pool.spawn(self.set_hostname, address)
        pool.join()

    def set_hostname(self, address):
        """
        Resolves hostname for the specified address.
        """
        hostname = raw_hostname(address)
        self.resolved['hostname'][address] = hostname


def raw_hostname(address):
    """
    Resolves hostname for the specified address using reverse DNS resolution.
    """
    hostname = address
    try:
        hostname = socket.gethostbyaddr(address)[0]
    except (socket.gaierror, socket.herror) as err:
        logging.debug("%s: %s", address, err)
    return hostname


def raw_geoip(address):
    """
    Resolves GeoIP data for the specified address using MaxMind databases.
    """
    city = None
    country = None
    latitude = 0.0
    longitude = 0.0
    timezone = None
    asn = None
    org = None

    geoip_record = None
    prec = Decimal('.000001')
    if address.endswith(".onion"):
        geoip_record = None
    elif ":" in address:
        geoip_record = GEOIP6.record_by_addr(address)
    else:
        geoip_record = GEOIP4.record_by_addr(address)
    if geoip_record:
        city = geoip_record['city']
        country = geoip_record['country_code']
        latitude = float(Decimal(geoip_record['latitude']).quantize(prec))
        longitude = float(Decimal(geoip_record['longitude']).quantize(prec))
        timezone = geoip_record['time_zone']

    asn_record = None
    if address.endswith(".onion"):
        asn_record = "TOR Tor network"
    elif ":" in address:
        asn_record = ASN6.org_by_addr(address)
    else:
        asn_record = ASN4.org_by_addr(address)
    if asn_record:
        data = asn_record.split(" ", 1)
        asn = data[0]
        if len(data) > 1:
            org = data[1]

    return (city, country, latitude, longitude, timezone, asn, org)


def init_conf(argv):
    """
    Populates CONF with key-value pairs from configuration file.
    """
    conf = ConfigParser()
    conf.read(argv[1])
    CONF['logfile'] = conf.get('resolve', 'logfile')
    CONF['magic_number'] = unhexlify(conf.get('resolve', 'magic_number'))
    CONF['db'] = conf.getint('resolve', 'db')
    CONF['debug'] = conf.getboolean('resolve', 'debug')
    CONF['ttl'] = conf.getint('resolve', 'ttl')


def main(argv):
    if len(argv) < 2 or not os.path.exists(argv[1]):
        print("Usage: resolve.py [config]")
        return 1

    # Initialize global conf
    init_conf(argv)

    # Initialize logger
    loglevel = logging.INFO
    if CONF['debug']:
        loglevel = logging.DEBUG

    logformat = ("%(filename)s %(lineno)d  (%(funcName)s) "
                 "%(message)s")
    logging.basicConfig(level=loglevel,
                        format=logformat,
                        filename=CONF['logfile'],
                        filemode='w')
    print("Log: {}, press CTRL+C to terminate..".format(CONF['logfile']))

    global REDIS_CONN
    REDIS_CONN = new_redis_conn(db=CONF['db'])

    subscribe_key = 'snapshot:{}'.format(hexlify(CONF['magic_number']))
    publish_key = 'resolve:{}'.format(hexlify(CONF['magic_number']))

    pubsub = REDIS_CONN.pubsub()
    pubsub.subscribe(subscribe_key)
    while True:
        msg = pubsub.get_message()
        if msg is None:
            time.sleep(0.001)  # 1 ms artificial intrinsic latency.
            continue
        # 'snapshot' message is published by ping.py after establishing
        # connection with nodes from a new snapshot.
        if msg['channel'] == subscribe_key and msg['type'] == 'message':
            timestamp = int(msg['data'])
            logging.info("Timestamp: %d", timestamp)
            nodes = REDIS_CONN.smembers('opendata')
            logging.info("Nodes: %d", len(nodes))
            addresses = set([eval(node)[0] for node in nodes])
            resolve = Resolve(addresses=addresses)
            resolve.resolve_addresses()
            REDIS_CONN.publish(publish_key, timestamp)

    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
