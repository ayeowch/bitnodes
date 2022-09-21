#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# resolve.py - Resolves hostname and GeoIP data for each reachable node.
#
# Copyright (c) Addy Yeow <ayeowch@gmail.com>
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
import redis
import redis.connection
import socket
import sys
import time
from binascii import hexlify
from binascii import unhexlify
from collections import defaultdict
from configparser import ConfigParser
from decimal import Decimal
from geoip2.errors import AddressNotFoundError

from utils import GeoIp
from utils import new_redis_conn

redis.connection.socket = gevent.socket

CONF = {}
GEO_PREC = Decimal('.0001')


class Resolve(object):
    """
    Implements hostname and GeoIP resolver.
    """
    def __init__(self, addresses=None, redis_conn=None):
        self.addresses = addresses
        self.redis_conn = redis_conn
        if redis_conn:
            self.redis_pipe = redis_conn.pipeline()
        else:
            self.redis_pipe = None
        self.resolved = defaultdict(dict)
        self.geoip = GeoIp()

    def resolve_addresses(self):
        """
        Resolves hostname for up to 1000 new addresses and GeoIP data for all
        addresses.
        """
        start = time.time()

        idx = 0
        for address in self.addresses:
            key = f'resolve:{address}'

            ttl = self.redis_conn.ttl(key)
            expiring = False
            if ttl < 0.1 * CONF['ttl']:  # Less than 10% of initial TTL.
                expiring = True

            if expiring and idx < 1000 and not address.endswith('.onion'):
                self.resolved['hostname'][address] = None
                idx += 1

            self.resolved['geoip'][address] = None

        logging.info(f"GeoIP: {len(self.resolved['geoip'])}", )
        self.resolve_geoip()

        logging.info(f"Hostname: {len(self.resolved['hostname'])}")
        self.resolve_hostname()

        self.cache_resolved()

        end = time.time()
        elapsed = end - start
        logging.info(f'Elapsed: {elapsed}')

    def cache_resolved(self):
        """
        Caches resolved addresses in Redis.
        """
        resolved = 0
        for address, geoip in self.resolved['geoip'].items():
            if geoip[1] or geoip[5]:
                resolved += 1  # country/asn is set.
            key = f'resolve:{address}'
            self.redis_pipe.hset(key, 'geoip', str(geoip))
            logging.debug(f'{key} geoip: {geoip}')
        logging.info(f'GeoIP: {resolved} resolved')

        resolved = 0
        for address, hostname in self.resolved['hostname'].items():
            if hostname != address:
                resolved += 1
            key = f'resolve:{address}'
            self.redis_pipe.hset(key, 'hostname', hostname)
            self.redis_pipe.expire(key, CONF['ttl'])
            logging.debug(f'{key} hostname: {hostname}')
        logging.info(f'Hostname: {resolved} resolved')

        self.redis_pipe.execute()

    def resolve_geoip(self):
        """
        Resolves GeoIP data for the unresolved addresses.
        """
        for address in self.resolved['geoip']:
            geoip = self.raw_geoip(address)
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
        hostname = self.raw_hostname(address)
        self.resolved['hostname'][address] = hostname

    def raw_hostname(self, address):
        """
        Resolves hostname for the specified address using reverse DNS
        resolution.
        """
        hostname = address
        try:
            hostname = socket.gethostbyaddr(address)[0]
        except (socket.gaierror, socket.herror) as err:
            logging.debug(f'{address}: {err}')
        return hostname

    def raw_geoip(self, address):
        """
        Resolves GeoIP data for the specified address using MaxMind databases.
        """
        country = None
        city = None
        lat = 0.0
        lng = 0.0
        timezone = None
        asn = None
        org = None

        if not address.endswith('.onion'):
            try:
                gcountry = self.geoip.country(address)
            except AddressNotFoundError:
                pass
            else:
                country = gcountry.country.iso_code

            try:
                gcity = self.geoip.city(address)
            except AddressNotFoundError:
                pass
            else:
                city = gcity.city.name
                if gcity.location.latitude is not None and \
                        gcity.location.longitude is not None:
                    lat = float(
                        Decimal(gcity.location.latitude).quantize(GEO_PREC))
                    lng = float(
                        Decimal(gcity.location.longitude).quantize(GEO_PREC))
                timezone = gcity.location.time_zone

        if address.endswith('.onion'):
            asn = 'TOR'
            org = 'Tor network'
        else:
            try:
                asn_record = self.geoip.asn(address)
            except AddressNotFoundError:
                pass
            else:
                asn = f'AS{asn_record.autonomous_system_number}'
                org = asn_record.autonomous_system_organization

        return (city, country, lat, lng, timezone, asn, org)


def cron():
    """
    Subscribes to 'snapshot' message from ping.py to resolve GeoIP data for
    addresses in the snapshot.
    """
    redis_conn = new_redis_conn(db=CONF['db'])

    magic_number = hexlify(CONF['magic_number']).decode()
    subscribe_key = f'snapshot:{magic_number}'
    publish_key = f'resolve:{magic_number}'

    pubsub = redis_conn.pubsub()
    pubsub.subscribe(subscribe_key)

    while True:
        msg = pubsub.get_message()
        if msg is None:
            time.sleep(0.1)  # 100 ms artificial intrinsic latency.
            continue

        channel = msg['channel'].decode()

        # 'snapshot' message is published by ping.py after establishing
        # connection with nodes from a new snapshot.
        if channel == subscribe_key and msg['type'] == 'message':
            timestamp = int(msg['data'])
            logging.info(f'Timestamp: {timestamp}')

            nodes = redis_conn.smembers('opendata')
            logging.info(f'Nodes: {len(nodes)}')

            addresses = set([eval(node)[0] for node in nodes])
            resolve = Resolve(addresses=addresses, redis_conn=redis_conn)
            resolve.resolve_addresses()

            redis_conn.publish(publish_key, timestamp)


def init_conf(config):
    """
    Populates CONF with key-value pairs from configuration file.
    """
    conf = ConfigParser()
    conf.read(config)
    CONF['logfile'] = conf.get('resolve', 'logfile')
    CONF['magic_number'] = unhexlify(conf.get('resolve', 'magic_number'))
    CONF['db'] = conf.getint('resolve', 'db')
    CONF['debug'] = conf.getboolean('resolve', 'debug')
    CONF['ttl'] = conf.getint('resolve', 'ttl')


def main(argv):
    if len(argv) < 2 or not os.path.exists(argv[1]):
        print('Usage: resolve.py [config]')
        return 1

    # Initialize global conf.
    init_conf(argv[1])

    # Initialize logger.
    loglevel = logging.INFO
    if CONF['debug']:
        loglevel = logging.DEBUG

    logformat = ('[%(process)d] %(asctime)s,%(msecs)05.1f %(levelname)s '
                 '(%(funcName)s) %(message)s')
    logging.basicConfig(level=loglevel,
                        format=logformat,
                        filename=CONF['logfile'],
                        filemode='w')
    print(f"Log: {CONF['logfile']}, press CTRL+C to terminate..")

    cron()

    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
