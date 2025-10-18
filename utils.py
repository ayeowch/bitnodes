#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# utils.py - Common helper methods.
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
Common helper methods.
"""

from gevent import monkey

monkey.patch_all()

import functools
import logging
import os
import random
import time
from ipaddress import ip_network

import redis
import requests
from geoip2.database import Reader
from maxminddb.errors import InvalidDatabaseError


class GeoIp(object):
    """
    MaxMind databases.
    """

    geoip_dir = os.path.join(os.path.dirname(__file__), "geoip")

    city_db = os.path.join(geoip_dir, "GeoLite2-City.mmdb")
    country_db = os.path.join(geoip_dir, "GeoLite2-Country.mmdb")
    asn_db = os.path.join(geoip_dir, "GeoLite2-ASN.mmdb")

    def __init__(self):
        # Retry on InvalidDatabaseError due to geoip/update.sh updating
        # *.mmdb that may cause this exception temporarily.
        for i in range(10):
            try:
                self.geoip_city = Reader(self.city_db)
                self.geoip_country = Reader(self.country_db)
                self.geoip_asn = Reader(self.asn_db)
            except (InvalidDatabaseError, IOError) as err:
                logging.warning("%s", err)
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


def init_logger(logfile, debug=False, filemode="w"):
    loglevel = logging.DEBUG if debug else logging.INFO
    logformat = "[%(process)d] %(asctime)s %(levelname)s (%(funcName)s) %(message)s"
    logging.basicConfig(
        level=loglevel, format=logformat, filename=logfile, filemode=filemode
    )
    print(f"Log: {logfile}, press CTRL+C to terminate..")


def new_redis_conn(db=0):
    """
    Return new instance of Redis connection with the right db selected.
    """
    socket = os.environ.get("REDIS_SOCKET", None)
    password = os.environ.get("REDIS_PASSWORD", None)
    return redis.StrictRedis(db=db, password=password, unix_socket_path=socket)


def get_keys(redis_conn, pattern, count=500):
    """
    Return Redis keys matching pattern by iterating the keys space.
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
    Return CIDR notation to represent the address and its prefix.
    """
    network = ip_network(f"{address}/{prefix}", strict=False)
    return f"{network.network_address}/{prefix}"


def http_get(url, timeout=15):
    """
    Return HTTP response on success and None otherwise.
    """
    try:
        response = requests.get(url, timeout=timeout)
    except requests.exceptions.RequestException as err:
        logging.warning("%s", err)
    else:
        if response.status_code == 200:
            return response
    return None


def http_get_txt(url, timeout=15):
    """
    Return HTTP text on success and empty string otherwise.
    """
    response = http_get(url, timeout=timeout)
    if response is not None:
        return response.content.decode()
    return ""


def conf_range(conf, section, name):
    """
    Return range value for the specified ConfigParser configuration option.
    """
    val = conf.get(section, name).strip()
    vals = sorted([int(i.strip()) for i in val.split("-")])
    if len(vals) == 2:
        return [vals[0], vals[1]]
    return [vals[0], vals[0]]


def conf_list(conf, section, name, func=str):
    """
    Return list of items for the specified ConfigParser configuration option.
    """
    val = conf.get(section, name).strip()
    if not val:
        return set()

    return txt_items(val, func=func)


def txt_items(txt, func=str):
    """
    Return set of items from the specified text.
    """
    items = set()

    lines = txt.strip().splitlines()
    for line in lines:
        line = line.split("#")[0].split(";")[0].strip()  # Strip inline comment.
        if line:
            items.add(func(line))

    return items


def ip_port_list(items):
    """
    Return list of tuples of IP and port from the specified items.
    """
    return [
        (item.rsplit(":", 1)[0].strip("[").strip("]"), int(item.rsplit(":", 1)[1]))
        for item in items
    ]


def throttle_run(ttl=None):
    """
    Decorator to run function at most once every ttl seconds.
    """

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if callable(ttl):
                val = ttl()
                if isinstance(val, (tuple, list)) and len(val) == 2:
                    # Cluster TTL around the middle of the range.
                    a, b = val
                    mode = (a + b) / 2
                    seconds = random.triangular(a, b, mode)
                else:
                    # Callable returning TTL.
                    seconds = float(val)
            else:
                # Fixed TTL.
                seconds = ttl

            now = time.monotonic()
            last_run = getattr(wrapper, "_last_run", None)
            if last_run is not None and now - last_run < seconds:
                return
            wrapper._last_run = now
            return func(*args, **kwargs)

        return wrapper

    return decorator
