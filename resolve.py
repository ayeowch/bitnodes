#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# resolve.py - Resolve hostname and GeoIP data for each reachable node.
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
Resolve hostname and GeoIP data for each reachable node.
"""

from gevent import monkey

monkey.patch_all()

import json
import logging
import os
import socket
import sys
import time
from collections import defaultdict
from configparser import ConfigParser
from decimal import Decimal

import gevent
import gevent.pool
import redis.connection
from binascii import hexlify, unhexlify
from geoip2.errors import AddressNotFoundError

from protocol import ONION_SUFFIX
from utils import GeoIp, init_logger, new_redis_conn

redis.connection.socket = gevent.socket

CONF = {}
GEO_PREC = Decimal(".0001")


class Resolve(object):
    """
    Implement hostname and GeoIP resolver.
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
        Resolve hostname for up to 1000 new addresses and GeoIP data for all
        addresses.
        """
        start_t = time.monotonic()

        for address in self.addresses:
            key = f"resolve:{address}"
            self.redis_pipe.ttl(key)
        ttl_values = self.redis_pipe.execute()

        expiring = 0
        for address, ttl in zip(self.addresses, ttl_values):
            self.resolved["geoip"][address] = None

            if (
                ttl < 0.1 * CONF["ttl"]  # Less than 10% of initial TTL.
                and expiring < 1000
                and not address.endswith(ONION_SUFFIX)
            ):
                self.resolved["hostname"][address] = None
                expiring += 1

        logging.info("GeoIP: %d", len(self.resolved["geoip"]))
        self.resolve_geoip()

        logging.info("Hostname: %d", len(self.resolved["hostname"]))
        self.resolve_hostname()

        self.cache_resolved()

        logging.info("Elapsed: %.2f", time.monotonic() - start_t)

    def cache_resolved(self):
        """
        Cache resolved addresses in Redis.
        """
        resolved = 0
        for address, geoip in self.resolved["geoip"].items():
            if geoip[1] or geoip[5]:
                resolved += 1  # country/asn is set.
            key = f"resolve:{address}"
            self.redis_pipe.hset(key, "geoip", json.dumps(geoip))
            logging.debug("%s geoip: %s", key, geoip)
        logging.info("GeoIP: %d resolved", resolved)

        resolved = 0
        for address, hostname in self.resolved["hostname"].items():
            if hostname != address:
                resolved += 1
            key = f"resolve:{address}"
            self.redis_pipe.hset(key, "hostname", hostname)
            self.redis_pipe.expire(key, CONF["ttl"])
            logging.debug("%s hostname: %s", key, hostname)
        logging.info("Hostname: %d resolved", resolved)

        self.redis_pipe.execute()

    def resolve_geoip(self):
        """
        Resolve GeoIP data for the unresolved addresses.
        """
        for address in self.resolved["geoip"]:
            geoip = self.raw_geoip(address)
            self.resolved["geoip"][address] = geoip

    def resolve_hostname(self):
        """
        Concurrently resolve hostname for the unresolved addresses.
        """
        pool = gevent.pool.Pool(len(self.resolved["hostname"]))
        for address in self.resolved["hostname"]:
            pool.spawn(self.set_hostname, address)
        pool.join()

    def set_hostname(self, address):
        """
        Resolve hostname for the specified address.
        """
        hostname = self.raw_hostname(address)
        self.resolved["hostname"][address] = hostname

    def raw_hostname(self, address):
        """
        Resolve hostname for the specified address using reverse DNS
        resolution.
        """
        hostname = address
        try:
            with gevent.Timeout(3):
                hostname = socket.gethostbyaddr(address)[0]
        except (socket.gaierror, socket.herror, gevent.Timeout) as err:
            logging.debug("%s: %s", address, err)
        return hostname

    def raw_geoip(self, address):
        """
        Resolve GeoIP data for the specified address using MaxMind databases.
        """
        country = None
        city = None
        lat = 0.0
        lng = 0.0
        timezone = None
        asn = None
        org = None

        if not address.endswith(ONION_SUFFIX):
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
                if (
                    gcity.location.latitude is not None
                    and gcity.location.longitude is not None
                ):
                    lat = float(Decimal(gcity.location.latitude).quantize(GEO_PREC))
                    lng = float(Decimal(gcity.location.longitude).quantize(GEO_PREC))
                timezone = gcity.location.time_zone

        if address.endswith(ONION_SUFFIX):
            asn = "TOR"
            org = "Tor network"
        else:
            try:
                asn_record = self.geoip.asn(address)
            except AddressNotFoundError:
                pass
            else:
                asn = f"AS{asn_record.autonomous_system_number}"
                org = asn_record.autonomous_system_organization

        return (city, country, lat, lng, timezone, asn, org)


def cron():
    """
    Subscribe to 'snapshot' message from ping.py to resolve GeoIP data for
    addresses in the snapshot.
    """
    redis_conn = new_redis_conn(db=CONF["db"])

    magic_number = hexlify(CONF["magic_number"]).decode()
    subscribe_key = f"snapshot:{magic_number}"
    publish_key = f"resolve:{magic_number}"

    pubsub = redis_conn.pubsub()
    pubsub.subscribe(subscribe_key)

    while True:
        msg = pubsub.get_message()
        if msg is None:
            time.sleep(0.1)  # 100 ms artificial intrinsic latency.
            continue

        channel = msg["channel"].decode()

        # 'snapshot' message is published by ping.py after establishing
        # connection with nodes from a new snapshot.
        if channel == subscribe_key and msg["type"] == "message":
            timestamp = int(msg["data"])
            logging.info("Timestamp: %d", timestamp)

            nodes = redis_conn.zrangebyscore("opendata", "-inf", "+inf")
            logging.info("Nodes: %d", len(nodes))

            addresses = set([json.loads(node)[0] for node in nodes])
            resolve = Resolve(addresses=addresses, redis_conn=redis_conn)
            resolve.resolve_addresses()

            redis_conn.publish(publish_key, timestamp)


def init_conf(config):
    """
    Populate CONF with key-value pairs from configuration file.
    """
    conf = ConfigParser()
    conf.read(config)
    CONF["logfile"] = conf.get("resolve", "logfile")
    CONF["magic_number"] = unhexlify(conf.get("resolve", "magic_number"))
    CONF["db"] = conf.getint("resolve", "db")
    CONF["debug"] = conf.getboolean("resolve", "debug")
    CONF["ttl"] = conf.getint("resolve", "ttl")


def main(argv):
    if len(argv) < 2 or not os.path.exists(argv[1]):
        print("Usage: resolve.py [config]")
        return 1

    # Initialize global conf.
    init_conf(argv[1])

    # Initialize logger.
    init_logger(CONF["logfile"], debug=CONF["debug"])

    cron()

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
