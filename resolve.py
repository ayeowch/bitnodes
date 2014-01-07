#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# resolve.py - Resolves hostname and GeoIP data for each reachable node.
#
# Copyright (c) 2013 Addy Yeow Chin Heng <ayeowch@gmail.com>
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

import gevent
import logging
import os
import pygeoip
import random
import redis
import redis.connection
import sys
from gevent import socket

redis.connection.socket = socket

# Global instance of Redis connection
REDIS_CONN = redis.StrictRedis()

# MaxMind databases
GEOIP4 = pygeoip.GeoIP("geoip/GeoLiteCity.dat", pygeoip.MMAP_CACHE)
GEOIP6 = pygeoip.GeoIP("geoip/GeoLiteCityv6.dat", pygeoip.MMAP_CACHE)
ASN4 = pygeoip.GeoIP("geoip/GeoIPASNum.dat", pygeoip.MMAP_CACHE)
ASN6 = pygeoip.GeoIP("geoip/GeoIPASNumv6.dat", pygeoip.MMAP_CACHE)

# Worker (resolver) status
RESOLVED = 2
FAILED = 1  # Failed socket.gethostbyaddr()


def resolve_nodes(nodes):
    """
    Spawns workers to resolve hostname and GeoIP data for all nodes.
    """
    addresses_1 = []  # Resolve hostname
    addresses_2 = []  # Resolve GeoIP data

    idx = 0
    for node in nodes:
        node = eval(node)
        address = node[0]
        if not REDIS_CONN.hexists('resolve:{}'.format(address), 'hostname'):
            if idx < 1000:
                addresses_1.append(address)
            idx += 1
        if not REDIS_CONN.hexists('resolve:{}'.format(address), 'geoip'):
            addresses_2.append(address)

    logging.info("Hostname: {} addresses".format(len(addresses_1)))
    workers = [gevent.spawn(set_hostname, address) for address in addresses_1]
    gevent.joinall(workers, timeout=15)

    (resolved, failed, aborted) = status(workers)
    logging.info("Hostname: {} resolved, {} failed, {} aborted".format(
        resolved, failed, aborted))

    logging.info("GeoIP: {} addresses".format(len(addresses_2)))
    workers = [gevent.spawn(set_geoip, address) for address in addresses_2]
    gevent.joinall(workers, timeout=15)

    (resolved, failed, aborted) = status(workers)
    logging.info("GeoIP: {} resolved, {} failed, {} aborted".format(
        resolved, failed, aborted))


def status(workers):
    """
    Summarizes resolve status for the spawned workers after a set timeout.
    """
    resolved = 0
    failed = 0
    aborted = 0  # Timed out

    for worker in workers:
        if worker.value == RESOLVED:
            resolved += 1
        elif worker.value == FAILED:
            failed += 1
        else:
            aborted += 1

    return (resolved, failed, aborted)


def set_data(address, field, value):
    """
    Stores data for an address in Redis with a TTL randomize within 2 hours
    spread to distribute expiring keys across multiple times.
    """
    ttl = random.randint(86400 - 3600, 86400 + 3600)
    redis_pipe = REDIS_CONN.pipeline()
    redis_pipe.hset('resolve:{}'.format(address), field, value)
    redis_pipe.expire('resolve:{}'.format(address), ttl)
    redis_pipe.execute()


def set_hostname(address):
    """
    Caches hostname for the specified address in Redis.
    """
    hostname = raw_hostname(address)
    set_data(address, 'hostname', hostname)
    if hostname != address:
        return RESOLVED
    return FAILED


def raw_hostname(address):
    """
    Resolves hostname for the specified address using reverse DNS resolution.
    """
    hostname = address
    try:
        hostname = socket.gethostbyaddr(address)[0]
    except socket.gaierror as err:
        logging.debug("{}: {}".format(address, err))
    except socket.herror as err:
        logging.debug("{}: {}".format(address, err))
    return hostname


def set_geoip(address):
    """
    Caches GeoIP data for the specified address in Redis.
    """
    geoip = raw_geoip(address)
    set_data(address, 'geoip', geoip)
    return RESOLVED


def raw_geoip(address):
    """
    Resolves GeoIP data for the specified address using MaxMind databases.
    """
    city = None
    country = None
    latitude = None
    longitude = None
    timezone = None
    asn = None
    org = None

    geoip_record = None
    if ":" in address:
        geoip_record = GEOIP6.record_by_addr(address)
    else:
        geoip_record = GEOIP4.record_by_addr(address)
    if geoip_record:
        city = geoip_record['city']
        country = geoip_record['country_code']
        latitude = geoip_record['latitude']
        longitude = geoip_record['longitude']
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


def main():
    logfile = os.path.basename(__file__).replace(".py", ".log")
    loglevel = logging.INFO
    logformat = ("%(asctime)s,%(msecs)05.1f %(levelname)s (%(funcName)s) "
                 "%(message)s")
    logging.basicConfig(level=loglevel,
                        format=logformat,
                        filename=logfile,
                        filemode='w')
    print("Writing output to {}, press CTRL+C to terminate..".format(logfile))

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
            resolve_nodes(nodes)
            REDIS_CONN.publish('resolve', timestamp)

    return 0


if __name__ == '__main__':
    sys.exit(main())
