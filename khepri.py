#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# khepri.py - Greenlets-based Bitcoin network crawler.
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
Greenlets-based Bitcoin network crawler.
"""

from gevent import monkey
monkey.patch_all()

import gevent
import json
import logging
import os
import random
import redis
import redis.connection
import requests
import socket
import sys
import time
from ConfigParser import ConfigParser

from protocol import ProtocolError, Connection, DEFAULT_PORT

redis.connection.socket = gevent.socket

# Seed nodes to bootstrap the initial crawl
SEEDS_URL = "http://getaddr.bitnodes.io/seeds/"

# Height is set at the start of a new crawl and updated periodically during
# crawl set refill.
HEIGHT_URL = "https://dazzlepod.com/bitcoin/getblockcount/"

# Known connection errors
NETWORK_ERRORS = [
    "ADDRESS FAMILY NOT SUPPORTED BY PROTOCOL FAMILY",
    "BROKEN PIPE",
    "CONNECTION REFUSED",
    "CONNECTION RESET BY PEER",
    "CONNECTION TIMED OUT",
    "INVALID ARGUMENT",
    "NETWORK IS UNREACHABLE",
    "NO ROUTE TO HOST",
    "OPERATION TIMED OUT",
    "PROTOCOL NOT AVAILABLE",
    "PERMISSION DENIED",
    "PROTOCOL ERROR",
]
TIMED_OUT = "TIMED OUT"

# Possible fields for a hash in Redis
TAG_FIELD = 'T'
DATA_FIELD = 'D'  # __VERSION__\t__USER_AGENT__\t__START_HEIGHT__

# Possible values for a tag field in Redis
GREEN = 'G'  # Reachable node
YELLOW = 'Y'  # Partially reachable node due to Bitcoin protocol error
ORANGE = 'O'  # No response from handshake
RED = 'R'  # Network error
BLUE = 'B'  # Timed out
VIOLET = 'V'  # Unhandled error

# Global instance of Redis connection
REDIS_CONN = redis.StrictRedis()

SETTINGS = {}


def enumerate_node(redis_pipe, key, version_msg, addr_msg):
    """
    Stores version information for a reachable node.
    Adds all peering nodes with max. age of 24 hours into the crawl set.
    """
    version = ""
    if 'version' in version_msg:
        version = version_msg['version']

    user_agent = ""
    if 'user_agent' in version_msg:
        user_agent = version_msg['user_agent']

    start_height = ""
    if 'start_height' in version_msg:
        start_height = version_msg['start_height']

    data = "{}\t{}\t{}".format(version, user_agent, start_height)
    redis_pipe.hset(key, DATA_FIELD, data)

    if 'addr_list' in addr_msg:
        now = time.time()

        for peer in addr_msg['addr_list']:
            address = peer['ipv4'] if peer['ipv4'] else peer['ipv6']
            timestamp = peer['timestamp']
            age = now - timestamp  # seconds

            # Add peering node with age <= 24 hours into crawl set
            if age >= 0 and age <= SETTINGS['max_age']:
                node = (address, peer['port'])
                redis_pipe.sadd('nodes', node)


def connect(redis_conn, key):
    """
    Establishes connection with a node to:
    1) Send version message
    2) Receive version and verack message
    3) Send getaddr message
    4) Receive addr message containing list of peering nodes
    Stores node in Redis with a set TTL.
    """
    handshake_msgs = []
    addr_msg = {}
    tag = None

    redis_conn.hset(key, TAG_FIELD, "")  # Set Redis hash for a new node

    address, port = key.split("-", 1)
    start_height = int(redis_conn.get('start_height'))

    connection = Connection((address, int(port)),
                            socket_timeout=SETTINGS['socket_timeout'],
                            user_agent=SETTINGS['user_agent'],
                            start_height=start_height)
    try:
        connection.open()
        handshake_msgs = connection.handshake()
        addr_msg = connection.getaddr()
    except ProtocolError as err:
        # e.g. node not accepting connection due to max. connections
        tag = YELLOW
    except socket.error as err:
        if err.strerror and err.strerror.upper() in NETWORK_ERRORS:
            tag = RED
        elif err.message and err.message.upper() == TIMED_OUT:
            tag = BLUE
        else:
            logging.warning("Unhandled socket error: {}".format(err))
            tag = VIOLET
    finally:
        connection.close()

    redis_pipe = redis_conn.pipeline()

    if len(handshake_msgs) > 0:
        tag = GREEN
        enumerate_node(redis_pipe, key, handshake_msgs[0], addr_msg)

    if tag is None:
        logging.debug("Orange node: {}".format(key))
        tag = ORANGE

    redis_pipe.hset(key, TAG_FIELD, tag)
    redis_pipe.expire(key, SETTINGS['ttl'])
    redis_pipe.execute()


def dump(nodes):
    """
    Dumps data for reachable nodes into timestamp-prefixed JSON file.
    """
    json_data = []

    logging.info("Reachable nodes: {}".format(len(nodes)))
    for node in nodes:
        data = REDIS_CONN.hget(node, DATA_FIELD)

        # Expired key
        if data is None:
            continue

        (version, user_agent, start_height) = data.split("\t")
        json_data.append(
            tuple(node.split("-", 1)) + (version, user_agent, start_height))

    json_output = os.path.join(SETTINGS['data'],
                               "{}.json".format(int(time.time())))
    open(json_output, 'w').write(json.dumps(json_data, indent=2))
    logging.info("Wrote {}".format(json_output))


def restart():
    """
    Dumps data for the reachable nodes into a JSON file.
    Fetches latest start height.
    Loads all reachable nodes from Redis into the crawl set.
    Removes keys for all nodes from current crawl.
    """
    nodes = []  # Reachable nodes

    keys = REDIS_CONN.keys('*-*')
    logging.debug("Keys: {}".format(len(keys)))

    redis_pipe = REDIS_CONN.pipeline()
    for key in keys:
        tag = REDIS_CONN.hget(key, TAG_FIELD)
        if tag == GREEN:
            nodes.append(key)
            redis_pipe.sadd('nodes', tuple(key.split("-", 1)))
        redis_pipe.delete(key)

    dump(nodes)

    set_start_height()

    redis_pipe.execute()


def cron():
    """
    Assigned to a worker to perform the following tasks periodically to
    maintain a continuous crawl:
    1) Reports the current number of nodes in crawl set
    2) Initiates a new crawl once the crawl set is empty
    """
    start = int(time.time())
    restart_threshold = 0

    while True:
        current_nodes = REDIS_CONN.scard('nodes')
        logging.info("Queue: {}".format(current_nodes))

        if current_nodes == 0:
            restart_threshold += 1
        else:
            restart_threshold = 0

        if restart_threshold == SETTINGS['restart_threshold']:
            elapsed = int(time.time()) - start
            logging.info("Elapsed: {}".format(elapsed))

            logging.info("Restarting")
            restart()

            start = int(time.time())
            restart_threshold = 0

        gevent.sleep(SETTINGS['cron_delay'])


def task():
    """
    Assigned to a worker to retrieve (pop) a node from the crawl set and
    attempt to establish connection with a new node.
    """
    redis_conn = redis.StrictRedis()

    while True:
        node = redis_conn.spop('nodes')  # Pop random node from set
        if node is None:
            gevent.sleep(1)
            continue

        node = eval(node)  # Convert string from Redis to tuple
        key = "{}-{}".format(node[0], node[1])

        # Skip IPv6 node
        if ":" in key and not SETTINGS['ipv6']:
            continue

        if redis_conn.exists(key):
            continue

        connect(redis_conn, key)
        gevent.sleep(random.randint(1, 2) * 0.1)


def set_start_height():
    """
    Fetches current start height from a remote source. The value is then set
    in Redis for use by all workers.
    """
    try:
        start_height = int(requests.get(HEIGHT_URL).text)
    except requests.exceptions.RequestException as err:
        logging.warning("{}".format(err))
        start_height = int(REDIS_CONN.get('start_height'))
    logging.info("Start height: {}".format(start_height))
    REDIS_CONN.set('start_height', start_height)


def init_settings(argv):
    """
    Populates SETTINGS with key-value pairs from configuration file.
    """
    conf = ConfigParser()
    conf.read(argv[1])
    SETTINGS['logfile'] = conf.get('khepri', 'logfile')
    SETTINGS['workers'] = conf.getint('khepri', 'workers')
    SETTINGS['debug'] = conf.getboolean('khepri', 'debug')
    SETTINGS['user_agent'] = conf.get('khepri', 'user_agent')
    SETTINGS['socket_timeout'] = conf.getint('khepri', 'socket_timeout')
    SETTINGS['cron_delay'] = conf.getint('khepri', 'cron_delay')
    SETTINGS['ttl'] = conf.getint('khepri', 'ttl')
    SETTINGS['restart_threshold'] = conf.getint('khepri', 'restart_threshold')
    SETTINGS['max_age'] = conf.getint('khepri', 'max_age')
    SETTINGS['ipv6'] = conf.getboolean('khepri', 'ipv6')
    SETTINGS['data'] = conf.get('khepri', 'data')
    if not os.path.exists(SETTINGS['data']):
        os.makedirs(SETTINGS['data'])


def main(argv):
    if len(argv) < 2 or not os.path.exists(argv[1]):
        print("Usage: khepri.py [config]")
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

    logging.info("Removing all keys")
    REDIS_CONN.flushall()

    # Get seed nodes
    seeds = json.loads(requests.get(SEEDS_URL).text)
    for seed in seeds:
        REDIS_CONN.sadd('nodes', (seed, DEFAULT_PORT))
    logging.info("Seeds: {}".format(len(seeds)))

    set_start_height()

    # Spawn workers (greenlets) including one worker reserved for cron tasks
    workers = []
    workers.append(gevent.spawn(cron))
    for _ in xrange(SETTINGS['workers'] - 1):
        workers.append(gevent.spawn(task))
    logging.info("Workers: {}".format(len(workers)))
    gevent.joinall(workers)

    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
