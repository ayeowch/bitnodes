#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# utils.py - Common helper methods.
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
Common helper methods.
"""

import logging
import os
import redis
import requests
import time
from geoip2.database import Reader
from ipaddress import ip_network
from maxminddb.errors import InvalidDatabaseError


class GeoIp(object):
    """
    MaxMind databases.
    """
    def __init__(self):
        # Retry on InvalidDatabaseError due to geoip/update.sh updating
        # *.mmdb that may cause this exception temporarily.
        for i in range(10):
            try:
                self.geoip_city = Reader("geoip/GeoLite2-City.mmdb")
                self.geoip_country = Reader("geoip/GeoLite2-Country.mmdb")
                self.geoip_asn = Reader("geoip/GeoLite2-ASN.mmdb")
            except (InvalidDatabaseError, IOError) as err:
                logging.warning(err)
                time.sleep(0.1)
                continue
            else:
                break

    def city(self, address):
        return self.geoip_city.city(address)

    def country(self, address):
        return self.geoip_country.country(address)

    def asn(self, address):
        return self.geoip_asn.asn(address)


def new_redis_conn(db=0):
    """
    Returns new instance of Redis connection with the right db selected.
    """
    socket = os.environ.get('REDIS_SOCKET', None)
    password = os.environ.get('REDIS_PASSWORD', None)
    return redis.StrictRedis(db=db, password=password, unix_socket_path=socket)


def get_keys(redis_conn, pattern, count=500):
    """
    Returns Redis keys matching pattern by iterating the keys space.
    """
    keys = []
    cursor = 0
    while True:
        (cursor, partial_keys) = redis_conn.scan(cursor, pattern, count)
        keys.extend(partial_keys)
        if cursor == 0:
            break
    return keys


def ip_to_network(address, prefix):
    """
    Returns CIDR notation to represent the address and its prefix.
    """
    network = ip_network(unicode("{}/{}".format(address, prefix)),
                         strict=False)
    return "{}/{}".format(network.network_address, prefix)


def http_get(url, timeout=15):
    try:
        response = requests.get(url, timeout=timeout)
    except requests.exceptions.RequestException as err:
        logging.warning(err)
    else:
        if response.status_code == 200:
            return response
    return None
