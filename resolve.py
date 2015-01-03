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

from decimal import Decimal
from gevent import socket
import gevent
import logging
import os
import pygeoip
import redis
import redis.connection
import sys
from collections import defaultdict
from ConfigParser import ConfigParser

redis.connection.socket = socket

# Redis connection setup
REDIS_SOCKET = os.environ.get('REDIS_SOCKET', "/tmp/redis.sock")
REDIS_PASSWORD = os.environ.get('REDIS_PASSWORD', None)
REDIS_CONN = redis.StrictRedis(unix_socket_path=REDIS_SOCKET,
                               password=REDIS_PASSWORD)

# MaxMind databases
GEOIP4 = pygeoip.GeoIP("geoip/GeoLiteCity.dat", pygeoip.MMAP_CACHE)
GEOIP6 = pygeoip.GeoIP("geoip/GeoLiteCityv6.dat", pygeoip.MMAP_CACHE)
ASN4 = pygeoip.GeoIP("geoip/GeoIPASNum.dat", pygeoip.MMAP_CACHE)
ASN6 = pygeoip.GeoIP("geoip/GeoIPASNumv6.dat", pygeoip.MMAP_CACHE)

SETTINGS = {}


class Resolve(object):
    """
    Implements hostname and GeoIP resolver.
    """
    def __init__(self, addresses):
        self.addresses = addresses
        self.resolved = defaultdict(int)
        self.redis_pipe = REDIS_CONN.pipeline()

    def resolve_addresses(self):
        """
        Resolves hostname for up to 1000 new addresses and GeoIP data for all
        addresses.
        """
        addresses_1 = []  # Resolve hostname
        addresses_2 = []  # Resolve GeoIP data

        idx = 0
        for address in self.addresses:
            key = 'resolve:{}'.format(address)

            # Reset TTL for existing key
            if REDIS_CONN.exists(key):
                self.redis_pipe.expire(key, SETTINGS['ttl'])

            if not REDIS_CONN.hexists(key, 'hostname'):
                if idx < 1000:
                    addresses_1.append(address)
                idx += 1

            if not REDIS_CONN.hexists(key, 'geoip'):
                addresses_2.append(address)

        logging.info("Hostname: {} addresses".format(len(addresses_1)))
        self.resolve_hostname(addresses_1)
        logging.info("Hostname: {} resolved".format(self.resolved['hostname']))

        logging.info("GeoIP: {} addresses".format(len(addresses_2)))
        self.resolve_geoip(addresses_2)
        logging.info("GeoIP: {} resolved".format(self.resolved['geoip']))

        self.redis_pipe.execute()

    def resolve_hostname(self, addresses):
        """
        Resolves hostname for the specified addresses concurrently and caches
        the results in Redis.
        """
        workers = [
            gevent.spawn(self.set_hostname, address) for address in addresses
        ]
        gevent.joinall(workers, timeout=15)

    def resolve_geoip(self, addresses):
        """
        Resolves GeoIP data for the specified addresses and caches the results
        in Redis.
        """
        for address in addresses:
            geoip = raw_geoip(address)
            if geoip[1] or geoip[5]:
                self.resolved['geoip'] += 1  # country/asn is set
            key = 'resolve:{}'.format(address)
            self.redis_pipe.hset(key, 'geoip', geoip)
            self.redis_pipe.expire(key, SETTINGS['ttl'])

    def set_hostname(self, address):
        """
        Caches hostname for the specified address in Redis.
        """
        hostname = raw_hostname(address)
        key = 'resolve:{}'.format(address)
        self.redis_pipe.hset(key, 'hostname', hostname)
        self.redis_pipe.expire(key, SETTINGS['ttl'])
        if hostname != address:
            self.resolved['hostname'] += 1


def raw_hostname(address):
    """
    Resolves hostname for the specified address using reverse DNS resolution.
    """
    hostname = address
    try:
        hostname = socket.gethostbyaddr(address)[0]
    except (socket.gaierror, socket.herror) as err:
        logging.debug("{}: {}".format(address, err))
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
    if ":" in address:
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
    if ":" in address:
        asn_record = ASN6.org_by_addr(address)
    else:
        asn_record = ASN4.org_by_addr(address)
    if asn_record:
        data = asn_record.split(" ", 1)
        asn = data[0]
        if len(data) > 1:
            org = data[1]

    return (city, country, latitude, longitude, timezone, asn, org)


def init_settings(argv):
    """
    Populates SETTINGS with key-value pairs from configuration file.
    """
    conf = ConfigParser()
    conf.read(argv[1])
    SETTINGS['logfile'] = conf.get('resolve', 'logfile')
    SETTINGS['debug'] = conf.getboolean('resolve', 'debug')
    SETTINGS['ttl'] = conf.getint('resolve', 'ttl')


def main(argv):
    if len(argv) < 2 or not os.path.exists(argv[1]):
        print("Usage: resolve.py [config]")
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
                        filemode='w')
    print("Writing output to {}, press CTRL+C to terminate..".format(
          SETTINGS['logfile']))

    pubsub = REDIS_CONN.pubsub()
    pubsub.subscribe('snapshot')
    for msg in pubsub.listen():
        # 'snapshot' message is published by ping.py after establishing
        # connection with nodes from a new snapshot.
        if msg['channel'] == 'snapshot' and msg['type'] == 'message':
            timestamp = int(msg['data'])
            logging.info("Timestamp: {}".format(timestamp))
            nodes = REDIS_CONN.smembers('opendata')
            logging.info("Nodes: {}".format(len(nodes)))
            addresses = set([eval(node)[0] for node in nodes])
            resolve = Resolve(addresses=addresses)
            resolve.resolve_addresses()
            REDIS_CONN.publish('resolve', timestamp)

    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
