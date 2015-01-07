#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# ping.py - Greenlets-based Bitcoin network pinger.
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
Greenlets-based Bitcoin network pinger.
"""

from gevent import monkey
monkey.patch_all()

import gevent
import gevent.pool
import glob
import json
import logging
import os
import random
import redis
import redis.connection
import socket
import sys
import time
from ConfigParser import ConfigParser

from protocol import ProtocolError, ConnectionError, Connection

redis.connection.socket = gevent.socket

# Redis connection setup
REDIS_SOCKET = os.environ.get('REDIS_SOCKET', "/tmp/redis.sock")
REDIS_PASSWORD = os.environ.get('REDIS_PASSWORD', None)
REDIS_CONN = redis.StrictRedis(unix_socket_path=REDIS_SOCKET,
                               password=REDIS_PASSWORD)

SETTINGS = {}


def ping(conn):
    """
    Sends a ping message to the specified node. Ping time is stored in Redis
    for round-trip time (RTT) calculation.
    """
    nonce = random.getrandbits(64)
    try:
        conn.ping(nonce=nonce)
    except socket.error as err:
        logging.debug("Closing {} ({})".format(conn.to_addr, err))
        return None

    last_ping = time.time()
    key = "ping:{}-{}:{}".format(conn.to_addr[0], conn.to_addr[1], nonce)
    REDIS_CONN.lpush(key, int(last_ping * 1000))  # in ms
    REDIS_CONN.expire(key, SETTINGS['ttl'])
    return last_ping


def keepalive(conn, version_msg):
    """
    Periodically sends a ping message and an inv for the consensus block to the
    specified node to maintain open connection. Open connections are tracked in
    open set with the associated data stored in opendata set in Redis.
    """
    version = version_msg.get('version', "")
    user_agent = version_msg.get('user_agent', "")
    services = version_msg.get('services', "")
    now = int(time.time())
    data = conn.to_addr + (version, user_agent, now, services)

    REDIS_CONN.sadd('opendata', data)

    wait = 60
    last_ping = now
    last_bestblockhash = None
    while True:
        if time.time() > last_ping + wait:
            last_ping = ping(conn)
            if last_ping is None:
                break
            try:
                wait = int(REDIS_CONN.get('elapsed'))
            except TypeError:
                pass
            bestblockhash = REDIS_CONN.get('bestblockhash')
            if last_bestblockhash != bestblockhash:
                try:
                    conn.inv(inventory=[(2, bestblockhash)])
                except socket.error as err:
                    logging.debug("Closing {} ({})".format(conn.to_addr, err))
                    break
                last_bestblockhash = bestblockhash
        # Sink received messages to flush them off socket buffer
        try:
            conn.get_messages()
        except socket.timeout as err:
            pass
        except (ProtocolError, ConnectionError, socket.error) as err:
            logging.debug("Closing {} ({})".format(conn.to_addr, err))
            break
        gevent.sleep(0.3)

    conn.close()

    REDIS_CONN.srem('opendata', data)


def task():
    """
    Assigned to a worker to retrieve (pop) a node from the reachable set and
    attempt to establish and maintain connection with the node.
    """
    node = REDIS_CONN.spop('reachable')
    if node is None:
        return
    (address, port, services, height) = eval(node)
    node = (address, port)

    if REDIS_CONN.sadd('open', node) == 0:
        logging.debug("Connection exists: {}".format(node))
        return

    handshake_msgs = []
    conn = Connection(node, (SETTINGS['source_address'], 0),
                      socket_timeout=SETTINGS['socket_timeout'],
                      protocol_version=SETTINGS['protocol_version'],
                      to_services=services,
                      from_services=SETTINGS['services'],
                      user_agent=SETTINGS['user_agent'],
                      height=height,
                      relay=SETTINGS['relay'])
    try:
        conn.open()
        handshake_msgs = conn.handshake()
    except (ProtocolError, ConnectionError, socket.error) as err:
        logging.debug("Closing {} ({})".format(conn.to_addr, err))
        conn.close()

    if len(handshake_msgs) == 0:
        REDIS_CONN.srem('open', node)
        return

    keepalive(conn, handshake_msgs[0])
    REDIS_CONN.srem('open', node)


def cron(pool):
    """
    Assigned to a worker to perform the following tasks periodically to
    maintain a continuous network-wide connections:

    [Master]
    1) Checks for a new snapshot
    2) Loads new reachable nodes into the reachable set in Redis
    3) Signals listener to get reachable nodes from opendata set
    4) Sets bestblockhash in Redis

    [Master/Slave]
    1) Spawns workers to establish and maintain connection with reachable nodes
    """
    snapshot = None

    while True:
        if SETTINGS['master']:
            new_snapshot = get_snapshot()

            if new_snapshot != snapshot:
                nodes = get_nodes(new_snapshot)
                if len(nodes) == 0:
                    continue

                logging.info("New snapshot: {}".format(new_snapshot))
                snapshot = new_snapshot

                logging.info("Nodes: {}".format(len(nodes)))

                reachable_nodes = set_reachable(nodes)
                logging.info("New reachable nodes: {}".format(reachable_nodes))

                # Allow connections to stabilize before publishing snapshot
                gevent.sleep(SETTINGS['cron_delay'])
                REDIS_CONN.publish('snapshot', int(time.time()))

            connections = REDIS_CONN.scard('open')
            logging.info("Connections: {}".format(connections))

            set_bestblockhash()

        for _ in xrange(min(REDIS_CONN.scard('reachable'), pool.free_count())):
            pool.spawn(task)

        workers = SETTINGS['workers'] - pool.free_count()
        logging.info("Workers: {}".format(workers))

        gevent.sleep(SETTINGS['cron_delay'])


def get_snapshot():
    """
    Returns latest JSON file (based on creation date) containing a snapshot of
    all reachable nodes from a completed crawl.
    """
    snapshot = None
    try:
        snapshot = max(glob.iglob("{}/*.json".format(SETTINGS['crawl_dir'])))
    except ValueError as err:
        logging.warning(err)
    return snapshot


def get_nodes(path):
    """
    Returns all reachable nodes from a JSON file.
    """
    nodes = []
    text = open(path, 'r').read()
    try:
        nodes = json.loads(text)
    except ValueError as err:
        logging.warning(err)
    return nodes


def set_reachable(nodes):
    """
    Adds reachable nodes that are not already in the open set into the
    reachable set in Redis. New workers can be spawned separately to establish
    and maintain connection with these nodes.
    """
    for node in nodes:
        address = node[0]
        port = node[1]
        services = node[2]
        height = node[3]
        if not REDIS_CONN.sismember('open', (address, port)):
            REDIS_CONN.sadd('reachable', (address, port, services, height))
    return REDIS_CONN.scard('reachable')


def set_bestblockhash():
    """
    Sets bestblockhash in Redis using the value of lastblockhash which has
    been validated by at least 50 percent of the reachable nodes.
    """
    lastblockhash = REDIS_CONN.get('lastblockhash')
    if lastblockhash is None:
        return

    bestblockhash = REDIS_CONN.get('bestblockhash')
    if bestblockhash == lastblockhash:
        return

    try:
        reachable_nodes = eval(REDIS_CONN.lindex("nodes", 0))[-1]
    except TypeError:
        logging.warning("nodes missing")
        return

    nodes = REDIS_CONN.zcard('inv:2:{}'.format(lastblockhash))
    if nodes >= reachable_nodes / 2.0:
        REDIS_CONN.set('bestblockhash', lastblockhash)
        logging.info("bestblockhash: {}".format(lastblockhash))


def init_settings(argv):
    """
    Populates SETTINGS with key-value pairs from configuration file.
    """
    conf = ConfigParser()
    conf.read(argv[1])
    SETTINGS['logfile'] = conf.get('ping', 'logfile')
    SETTINGS['workers'] = conf.getint('ping', 'workers')
    SETTINGS['debug'] = conf.getboolean('ping', 'debug')
    SETTINGS['source_address'] = conf.get('ping', 'source_address')
    SETTINGS['protocol_version'] = conf.getint('ping', 'protocol_version')
    SETTINGS['user_agent'] = conf.get('ping', 'user_agent')
    SETTINGS['services'] = conf.getint('ping', 'services')
    SETTINGS['relay'] = conf.getint('ping', 'relay')
    SETTINGS['socket_timeout'] = conf.getint('ping', 'socket_timeout')
    SETTINGS['cron_delay'] = conf.getint('ping', 'cron_delay')
    SETTINGS['ttl'] = conf.getint('ping', 'ttl')
    SETTINGS['crawl_dir'] = conf.get('ping', 'crawl_dir')
    if not os.path.exists(SETTINGS['crawl_dir']):
        os.makedirs(SETTINGS['crawl_dir'])

    # Set to True for master process
    SETTINGS['master'] = argv[2] == "master"


def main(argv):
    if len(argv) < 3 or not os.path.exists(argv[1]):
        print("Usage: ping.py [config] [master|slave]")
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
        logging.info("Removing all keys")
        REDIS_CONN.delete('reachable')
        REDIS_CONN.delete('open')
        REDIS_CONN.delete('opendata')

    # Initialize a pool of workers (greenlets)
    pool = gevent.pool.Pool(SETTINGS['workers'])
    pool.spawn(cron, pool)
    pool.join()

    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
