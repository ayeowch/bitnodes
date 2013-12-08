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
]
TIMED_OUT = "TIMED OUT"

# Key's name in Redis
R_PORT = 'P'
R_TAG = 'T'
R_USER_AGENT = 'U'
R_HEIGHT = 'H'

# Node's tag in Redis
GREEN = 'G'  # Reachable node
YELLOW = 'Y'  # No response from handshake
ORANGE = 'O'  # Bitcoin protocol error
RED = 'R'  # Network error
BLUE = 'B'  # Timed out

# Global instance of Redis connection
REDIS_CONN = redis.StrictRedis()

SETTINGS = {}


def connect(redis_conn, key, new):
    handshake_msgs = []
    addr_msg = {}
    tag = None

    if new:
        redis_conn.hset(key, R_TAG, "")  # Set Redis hash for a new node

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
        tag = ORANGE
    except socket.error as err:
        if err.strerror and err.strerror.upper() in NETWORK_ERRORS:
            tag = RED
        elif err.message and err.message.upper() == TIMED_OUT:
            tag = BLUE
        else:
            if SETTINGS['debug']:
                import pdb
                pdb.set_trace()
    finally:
        connection.close()

    redis_pipe = redis_conn.pipeline()

    if len(handshake_msgs) > 0:
        tag = GREEN

        if 'user_agent' in handshake_msgs[0]:
            redis_pipe.hset(key, R_USER_AGENT, handshake_msgs[0]['user_agent'])

        if 'start_height' in handshake_msgs[0]:
            redis_pipe.hset(key, R_HEIGHT, handshake_msgs[0]['start_height'])

        if 'addr_list' in addr_msg:
            now = time.time()

            for peer in addr_msg['addr_list']:
                node = (peer['ipv4'], peer['port'])

                timestamp = peer['timestamp']
                age = now - timestamp  # seconds

                # Add peering node with age <= 24 hours into crawl set
                if age >= 0 and age <= SETTINGS['max_age']:
                    redis_pipe.sadd('nodes', node)

    if tag is None:
        tag = YELLOW

    redis_pipe.hset(key, R_TAG, tag)
    redis_pipe.expire(key, SETTINGS['ttl'])
    redis_pipe.execute()


def refill():
    nodes = []  # Reachable (green) nodes
    redis_pipe = REDIS_CONN.pipeline()

    keys = REDIS_CONN.keys('*-*')
    logging.info("[refill] Keys: {}".format(len(keys)))

    for key in keys:
        tag = REDIS_CONN.hget(key, R_TAG)
        if tag == GREEN:
            nodes.append(key)
        redis_pipe.sadd('nodes', tuple(key.split("-", 1)))
    redis_pipe.execute()

    start_height = int(requests.get(HEIGHT_URL).text)
    logging.info("[refill] Start height: {}".format(start_height))
    REDIS_CONN.set('start_height', start_height)

    logging.info("[refill] Reachable nodes: {}".format(len(nodes)))
    open(SETTINGS['json_output'], 'w').write(json.dumps(nodes, indent=2))

    return time.time()


def cron():
    last_refill = time.time()

    while True:
        current_nodes = REDIS_CONN.scard('nodes')
        logging.info("[cron] Queue: {}".format(current_nodes))

        if time.time() - last_refill >= SETTINGS['refill_delay']:
            logging.info("[cron] Refilling queue")
            last_refill = refill()

        gevent.sleep(SETTINGS['cron_delay'])


def task():
    redis_conn = redis.StrictRedis()

    while True:
        node = redis_conn.spop('nodes')  # Pop random node from set
        if node is None:
            gevent.sleep(random.randint(10, 30) * 0.1)  # 1 - 3 secs.
            continue

        node = eval(node)  # Convert string from Redis to tuple
        key = "{}-{}".format(node[0], node[1])

        new = True
        if redis_conn.exists(key):
            if redis_conn.ttl(key) > 0.5 * SETTINGS['ttl']:
                continue
            new = False

        connect(redis_conn, key, new)
        gevent.sleep(random.randint(1, 3) * 0.1)  # 0.1 - 0.3 sec.


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
    SETTINGS['refill_delay'] = conf.getint('khepri', 'refill_delay')
    SETTINGS['max_age'] = conf.getint('khepri', 'max_age')
    SETTINGS['json_output'] = conf.get('khepri', 'json_output')


def main(argv):
    if len(argv) < 2 or not os.path.exists(argv[1]):
        print("Usage: khepri.py [config]")
        return 1

    # Initialize settings
    init_settings(argv)

    # Initialize logger
    loglevel = logging.INFO
    if SETTINGS['debug']:
        loglevel = logging.DEBUG

    logformat = ("%(asctime)s,%(msecs)05.1f %(levelname)s %(message)s")
    logging.basicConfig(level=loglevel,
                        format=logformat,
                        filename=SETTINGS['logfile'],
                        filemode='w')
    print("Writing output to {}, press CTRL+C to terminate..".format(
          SETTINGS['logfile']))

    logging.debug("Removing all keys")
    REDIS_CONN.flushall()

    # Get seed nodes
    seeds = 0
    for address in json.loads(requests.get(SEEDS_URL).text):
        REDIS_CONN.sadd('nodes', (address, DEFAULT_PORT))
        seeds += 1
    logging.info("Seeds: {}".format(seeds))

    # Get current start height
    start_height = int(requests.get(HEIGHT_URL).text)
    logging.info("Start height: {}".format(start_height))
    REDIS_CONN.set('start_height', start_height)

    # Spawn workers (greenlets) including one worker reserved for cron tasks
    workers = []
    workers.append(gevent.spawn(cron))
    for _ in xrange(SETTINGS['workers'] - 1):
        workers.append(gevent.spawn(task))
    logging.debug("Workers: {}".format(len(workers)))
    gevent.joinall(workers)

    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
