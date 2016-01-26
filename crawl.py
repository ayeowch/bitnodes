#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# crawl.py - Greenlets-based Bitcoin network crawler.
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
Greenlets-based Bitcoin network crawler.
"""

from gevent import monkey
monkey.patch_all()

import gevent
import json
import logging
import os
import redis
import redis.connection
import requests
import socket
import sys
import time
from base64 import b32decode
from binascii import hexlify
from collections import Counter
from ConfigParser import ConfigParser
from ipaddress import ip_network

from protocol import (ProtocolError, ConnectionError, Connection, TO_SERVICES,
                      DEFAULT_PORT, ONION_PREFIX)

redis.connection.socket = gevent.socket

# Redis connection setup
REDIS_SOCKET = os.environ.get('REDIS_SOCKET', "/tmp/redis.sock")
REDIS_PASSWORD = os.environ.get('REDIS_PASSWORD', None)
REDIS_CONN = redis.StrictRedis(unix_socket_path=REDIS_SOCKET,
                               password=REDIS_PASSWORD)

SETTINGS = {}


def enumerate_node(redis_pipe, addr_msgs, now):
    """
    Adds all peering nodes with max. age of 24 hours into the crawl set.
    """
    peers = 0

    for addr_msg in addr_msgs:
        if 'addr_list' in addr_msg:
            for peer in addr_msg['addr_list']:
                age = now - peer['timestamp']  # seconds

                # Add peering node with age <= 24 hours into crawl set
                if age >= 0 and age <= SETTINGS['max_age']:
                    address = peer['ipv4'] or peer['ipv6'] or peer['onion']
                    port = peer['port'] if peer['port'] > 0 else DEFAULT_PORT
                    services = peer['services']
                    if not address:
                        continue
                    if is_excluded(address):
                        logging.debug("Exclude: %s", address)
                        continue
                    redis_pipe.sadd('pending', (address, port, services))
                    peers += 1

    return peers


def connect(redis_conn, key):
    """
    Establishes connection with a node to:
    1) Send version message
    2) Receive version and verack message
    3) Send getaddr message
    4) Receive addr message containing list of peering nodes
    Stores state and height for node in Redis.
    """
    handshake_msgs = []
    addr_msgs = []

    redis_conn.hset(key, 'state', "")  # Set Redis hash for a new node

    (address, port, services) = key[5:].split("-", 2)
    services = int(services)
    height = redis_conn.get('height')
    if height:
        height = int(height)

    conn = Connection((address, int(port)),
                      (SETTINGS['source_address'], 0),
                      socket_timeout=SETTINGS['socket_timeout'],
                      proxy=SETTINGS['proxy'],
                      protocol_version=SETTINGS['protocol_version'],
                      to_services=services,
                      from_services=SETTINGS['services'],
                      user_agent=SETTINGS['user_agent'],
                      height=height,
                      relay=SETTINGS['relay'])
    try:
        logging.debug("Connecting to %s", conn.to_addr)
        conn.open()
        handshake_msgs = conn.handshake()
        addr_msgs = conn.getaddr()
    except (ProtocolError, ConnectionError, socket.error) as err:
        logging.debug("%s: %s", conn.to_addr, err)
    finally:
        conn.close()

    gevent.sleep(0.3)
    redis_pipe = redis_conn.pipeline()
    if len(handshake_msgs) > 0:
        version_msg = handshake_msgs[0]
        from_services = version_msg.get('services', 0)
        if from_services != services:
            logging.debug("%s Expected %d, got %d for services", conn.to_addr,
                          services, from_services)
            return
        height_key = "height:{}-{}-{}".format(address, port, services)
        redis_pipe.setex(height_key, SETTINGS['max_age'],
                         version_msg.get('height', 0))
        now = int(time.time())
        peers = enumerate_node(redis_pipe, addr_msgs, now)
        logging.debug("%s Peers: %d", conn.to_addr, peers)
        redis_pipe.hset(key, 'state', "up")
    redis_pipe.execute()


def dump(timestamp, nodes):
    """
    Dumps data for reachable nodes into timestamp-prefixed JSON file and
    returns most common height from the nodes.
    """
    json_data = []

    for node in nodes:
        (address, port, services) = node[5:].split("-", 2)
        height_key = "height:{}-{}-{}".format(address, port, services)
        try:
            height = int(REDIS_CONN.get(height_key))
        except TypeError:
            logging.warning("%s missing", height_key)
            height = 0
        json_data.append([address, int(port), int(services), height])

    if len(json_data) == 0:
        logging.warning("len(json_data): %d", len(json_data))
        return 0

    json_output = os.path.join(SETTINGS['crawl_dir'],
                               "{}.json".format(timestamp))
    open(json_output, 'w').write(json.dumps(json_data))
    logging.info("Wrote %s", json_output)

    return Counter([node[-1] for node in json_data]).most_common(1)[0][0]


def restart(timestamp):
    """
    Dumps data for the reachable nodes into a JSON file.
    Loads all reachable nodes from Redis into the crawl set.
    Removes keys for all nodes from current crawl.
    Updates excluded networks with current list of bogons.
    Updates number of reachable nodes and most common height in Redis.
    """
    nodes = []  # Reachable nodes

    keys = []
    cursor = 0
    while True:
        (cursor, partial_keys) = REDIS_CONN.scan(cursor, 'node:*')
        keys.extend(partial_keys)
        if cursor == 0:
            break
    logging.debug("Keys: %d", len(keys))

    redis_pipe = REDIS_CONN.pipeline()
    for key in keys:
        state = REDIS_CONN.hget(key, 'state')
        if state == "up":
            nodes.append(key)
            (address, port, services) = key[5:].split("-", 2)
            redis_pipe.sadd('pending', (address, int(port), int(services)))
        redis_pipe.delete(key)

    if SETTINGS['include_checked']:
        checked_nodes = REDIS_CONN.zrangebyscore(
            'check', timestamp - SETTINGS['max_age'], timestamp)
        for node in checked_nodes:
            (address, port, services) = eval(node)
            if is_excluded(address):
                logging.debug("Exclude: %s", address)
                continue
            redis_pipe.sadd('pending', (address, port, services))

    redis_pipe.execute()

    update_excluded_networks()

    reachable_nodes = len(nodes)
    logging.info("Reachable nodes: %d", reachable_nodes)
    REDIS_CONN.lpush('nodes', (timestamp, reachable_nodes))

    height = dump(timestamp, nodes)
    REDIS_CONN.set('height', height)
    logging.info("Height: %d", height)


def cron():
    """
    Assigned to a worker to perform the following tasks periodically to
    maintain a continuous crawl:
    1) Reports the current number of nodes in crawl set
    2) Initiates a new crawl once the crawl set is empty
    """
    start = int(time.time())

    while True:
        pending_nodes = REDIS_CONN.scard('pending')
        logging.info("Pending: %d", pending_nodes)

        if pending_nodes == 0:
            REDIS_CONN.set('crawl:master:state', "starting")
            now = int(time.time())
            elapsed = now - start
            REDIS_CONN.set('elapsed', elapsed)
            logging.info("Elapsed: %d", elapsed)
            logging.info("Restarting")
            restart(now)
            start = int(time.time())
            REDIS_CONN.set('crawl:master:state', "running")

        gevent.sleep(SETTINGS['cron_delay'])


def task():
    """
    Assigned to a worker to retrieve (pop) a node from the crawl set and
    attempt to establish connection with a new node.
    """
    redis_conn = redis.StrictRedis(unix_socket_path=REDIS_SOCKET,
                                   password=REDIS_PASSWORD)

    while True:
        if not SETTINGS['master']:
            while REDIS_CONN.get('crawl:master:state') != "running":
                gevent.sleep(SETTINGS['socket_timeout'])

        node = redis_conn.spop('pending')  # Pop random node from set
        if node is None:
            gevent.sleep(1)
            continue

        node = eval(node)  # Convert string from Redis to tuple

        # Skip IPv6 node
        if ":" in node[0] and not SETTINGS['ipv6']:
            continue

        key = "node:{}-{}-{}".format(node[0], node[1], node[2])
        if redis_conn.exists(key):
            continue

        connect(redis_conn, key)


def set_pending():
    """
    Initializes pending set in Redis with a list of reachable nodes from DNS
    seeders and hardcoded list of .onion nodes to bootstrap the crawler.
    """
    for seeder in SETTINGS['seeders']:
        nodes = []
        try:
            nodes = socket.getaddrinfo(seeder, None)
        except socket.gaierror as err:
            logging.warning("%s", err)
            continue
        for node in nodes:
            address = node[-1][0]
            if is_excluded(address):
                logging.debug("Exclude: %s", address)
                continue
            logging.debug("%s: %s", seeder, address)
            REDIS_CONN.sadd('pending', (address, DEFAULT_PORT, TO_SERVICES))
    if SETTINGS['onion']:
        for address in SETTINGS['onion_nodes']:
            REDIS_CONN.sadd('pending', (address, DEFAULT_PORT, TO_SERVICES))


def is_excluded(address):
    """
    Returns True if address is found in exclusion list, False if otherwise.
    """
    if address.endswith(".onion"):
        address = onion_to_ipv6(address)
    address_family = socket.AF_INET
    key = 'exclude_ipv4_networks'
    if ":" in address:
        address_family = socket.AF_INET6
        key = 'exclude_ipv6_networks'
    try:
        addr = int(hexlify(socket.inet_pton(address_family, address)), 16)
    except socket.error:
        logging.warning("Bad address: %s", address)
        return True
    return any([(addr & net[1] == net[0]) for net in SETTINGS[key]])


def onion_to_ipv6(address):
    """
    Returns IPv6 equivalent of an .onion address.
    """
    ipv6_bytes = ONION_PREFIX + b32decode(address[:-6], True)
    return socket.inet_ntop(socket.AF_INET6, ipv6_bytes)


def list_excluded_networks(txt, networks=None):
    """
    Converts list of networks from configuration file into a list of tuples of
    network address and netmask to be excluded from the crawl.
    """
    if networks is None:
        networks = set()
    lines = txt.strip().split("\n")
    for line in lines:
        line = line.split('#')[0].strip()
        try:
            network = ip_network(unicode(line))
        except ValueError:
            continue
        else:
            networks.add((int(network.network_address), int(network.netmask)))
    return networks


def update_excluded_networks():
    """
    Adds bogons into the excluded IPv4 networks.
    """
    if not SETTINGS['exclude_ipv4_bogons']:
        return
    url = "http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt"
    try:
        response = requests.get(url, timeout=15)
    except requests.exceptions.RequestException as err:
        logging.warning(err)
    else:
        if response.status_code == 200:
            SETTINGS['exclude_ipv4_networks'] = list_excluded_networks(
                response.content,
                networks=SETTINGS['initial_exclude_ipv4_networks'])
            logging.info("%d", len(SETTINGS['exclude_ipv4_networks']))


def init_settings(argv):
    """
    Populates SETTINGS with key-value pairs from configuration file.
    """
    conf = ConfigParser()
    conf.read(argv[1])
    SETTINGS['logfile'] = conf.get('crawl', 'logfile')
    SETTINGS['seeders'] = conf.get('crawl', 'seeders').strip().split("\n")
    SETTINGS['workers'] = conf.getint('crawl', 'workers')
    SETTINGS['debug'] = conf.getboolean('crawl', 'debug')
    SETTINGS['source_address'] = conf.get('crawl', 'source_address')
    SETTINGS['protocol_version'] = conf.getint('crawl', 'protocol_version')
    SETTINGS['user_agent'] = conf.get('crawl', 'user_agent')
    SETTINGS['services'] = conf.getint('crawl', 'services')
    SETTINGS['relay'] = conf.getint('crawl', 'relay')
    SETTINGS['socket_timeout'] = conf.getint('crawl', 'socket_timeout')
    SETTINGS['cron_delay'] = conf.getint('crawl', 'cron_delay')
    SETTINGS['max_age'] = conf.getint('crawl', 'max_age')
    SETTINGS['ipv6'] = conf.getboolean('crawl', 'ipv6')

    SETTINGS['exclude_ipv4_networks'] = list_excluded_networks(
        conf.get('crawl', 'exclude_ipv4_networks'))
    SETTINGS['exclude_ipv6_networks'] = list_excluded_networks(
        conf.get('crawl', 'exclude_ipv6_networks'))

    SETTINGS['exclude_ipv4_bogons'] = conf.getboolean('crawl',
                                                      'exclude_ipv4_bogons')

    SETTINGS['initial_exclude_ipv4_networks'] = \
        SETTINGS['exclude_ipv4_networks']

    SETTINGS['onion'] = conf.getboolean('crawl', 'onion')
    SETTINGS['proxy'] = None
    if SETTINGS['onion']:
        proxy = conf.get('crawl', 'proxy').split(":")
        SETTINGS['proxy'] = (proxy[0], int(proxy[1]))
    SETTINGS['onion_nodes'] = conf.get('crawl',
                                       'onion_nodes').strip().split("\n")

    SETTINGS['include_checked'] = conf.getboolean('crawl', 'include_checked')

    SETTINGS['crawl_dir'] = conf.get('crawl', 'crawl_dir')
    if not os.path.exists(SETTINGS['crawl_dir']):
        os.makedirs(SETTINGS['crawl_dir'])

    # Set to True for master process
    SETTINGS['master'] = argv[2] == "master"


def main(argv):
    if len(argv) < 3 or not os.path.exists(argv[1]):
        print("Usage: crawl.py [config] [master|slave]")
        return 1

    # Initialize global settings
    init_settings(argv)

    # Initialize logger
    loglevel = logging.INFO
    if SETTINGS['debug']:
        loglevel = logging.DEBUG

    logformat = ("[%(process)d] %(asctime)s,%(msecs)05.1f %(levelname)s "
                 "(%(funcName)s) %(message)s")
    logging.basicConfig(level=loglevel,
                        format=logformat,
                        filename=SETTINGS['logfile'],
                        filemode='a')
    print("Writing output to {}, press CTRL+C to terminate..".format(
        SETTINGS['logfile']))

    if SETTINGS['master']:
        REDIS_CONN.set('crawl:master:state', "starting")
        logging.info("Removing all keys")
        keys = []
        cursor = 0
        while True:
            (cursor, partial_keys) = REDIS_CONN.scan(cursor, 'node:*')
            keys.extend(partial_keys)
            if cursor == 0:
                break
        redis_pipe = REDIS_CONN.pipeline()
        for key in keys:
            redis_pipe.delete(key)
        redis_pipe.delete('pending')
        redis_pipe.execute()
        set_pending()
        update_excluded_networks()

    # Spawn workers (greenlets) including one worker reserved for cron tasks
    workers = []
    if SETTINGS['master']:
        workers.append(gevent.spawn(cron))
    for _ in xrange(SETTINGS['workers'] - len(workers)):
        workers.append(gevent.spawn(task))
    logging.info("Workers: %d", len(workers))
    gevent.joinall(workers)

    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
