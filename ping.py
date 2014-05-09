#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# ping.py - Greenlets-based Bitcoin network pinger.
#
# Copyright (c) 2014 Addy Yeow Chin Heng <ayeowch@gmail.com>
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
import redis
import redis.connection
import socket
import sys
import time
from ConfigParser import ConfigParser

from protocol import ProtocolError, Connection

redis.connection.socket = gevent.socket

# Redis connection setup
REDIS_SOCKET = os.environ.get('REDIS_SOCKET', "/tmp/redis.sock")
REDIS_PASSWORD = os.environ.get('REDIS_PASSWORD', None)
REDIS_CONN = redis.StrictRedis(unix_socket_path=REDIS_SOCKET,
                               password=REDIS_PASSWORD)

SETTINGS = {}


def keepalive(connection, version_msg):
    """
    Sends a ping message 3 minutes to the specified node to maintain open
    connection and yields received inv messages. Open connections are tracked
    in open set with the associated data stored in opendata set in Redis.
    """
    node = connection.to_addr
    version = version_msg.get('version', "")
    user_agent = version_msg.get('user_agent', "")
    now = int(time.time())
    data = node + (version, user_agent, now)

    REDIS_CONN.sadd('open', node)
    REDIS_CONN.sadd('opendata', data)

    last_ping = now

    while True:
        if time.time() > last_ping + 180:
            try:
                connection.ping()
            except socket.error as err:
                logging.debug("Closing {} ({})".format(node, err))
                break
            last_ping = time.time()

        try:
            msgs = connection.get_messages(commands=["inv"])
        except socket.timeout as err:
            logging.debug("{}: {}".format(node, err))
        except (ProtocolError, socket.error) as err:
            logging.debug("Closing {} ({})".format(node, err))
            break
        else:
            yield msgs

        # Cut CPU usage at the expense of 50ms slack for inv timestamps
        gevent.sleep(0.05)

    connection.close()

    REDIS_CONN.srem('open', node)
    REDIS_CONN.srem('opendata', data)


def task():
    """
    Assigned to a worker to retrieve (pop) a node from the reachable set and
    attempt to establish and maintain connection with the node.
    """
    node = REDIS_CONN.spop('reachable')
    if node is None:
        return
    (address, port, start_height) = eval(node)

    handshake_msgs = []
    connection = Connection((address, port),
                            socket_timeout=SETTINGS['socket_timeout'],
                            user_agent=SETTINGS['user_agent'],
                            start_height=start_height)

    try:
        connection.open()
        handshake_msgs = connection.handshake()
    except (ProtocolError, socket.error) as err:
        logging.debug("Closing {} ({})".format(connection.to_addr, err))
        connection.close()

    if len(handshake_msgs) == 0:
        return

    for msgs in keepalive(connection, handshake_msgs[0]):
        save_inv(connection.to_addr, msgs)


def save_inv(node, msgs):
    """
    Adds inv messages received from node into the inv set in Redis.
    """
    redis_pipe = REDIS_CONN.pipeline()

    for msg in msgs:
        logging.debug("{}: {} inv".format(node, msg['count']))
        for inv in msg['inventory']:
            logging.debug("{}:{}".format(inv['type'], inv['hash']))
            key = "inv:{}:{}".format(inv['type'], inv['hash'])
            redis_pipe.zadd(key, msg['timestamp'], node)
            redis_pipe.expire(key, 10800)

    redis_pipe.execute()


def cron(pool):
    """
    Assigned to a worker to perform the following tasks periodically to
    maintain a continuous network-wide connections:

    [Master]
    1) Checks for a new snapshot
    2) Loads new reachable nodes into the reachable set in Redis
    3) Signals listener to get reachable nodes from opendata set

    [Master/Slave]
    1) Spawns workers to establish and maintain connection with reachable nodes
    """
    snapshot = None

    while True:
        if SETTINGS['master']:
            new_snapshot = get_snapshot()

            if new_snapshot != snapshot:
                logging.info("New snapshot: {}".format(new_snapshot))
                nodes = get_nodes(new_snapshot)
                if len(nodes) == 0:
                    continue
                snapshot = new_snapshot

                logging.info("Nodes: {}".format(len(nodes)))

                reachable_nodes = set_reachable(nodes)
                logging.info("New reachable nodes: {}".format(reachable_nodes))

                REDIS_CONN.publish('snapshot', int(time.time()))

            connections = REDIS_CONN.scard('open')
            logging.info("Connections: {}".format(connections))

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
        start_height = node[2]
        if not REDIS_CONN.sismember('open', (address, port)):
            REDIS_CONN.sadd('reachable', (address, port, start_height))
    return REDIS_CONN.scard('reachable')


def init_settings(argv):
    """
    Populates SETTINGS with key-value pairs from configuration file.
    """
    conf = ConfigParser()
    conf.read(argv[1])
    SETTINGS['logfile'] = conf.get('ping', 'logfile')
    SETTINGS['workers'] = conf.getint('ping', 'workers')
    SETTINGS['debug'] = conf.getboolean('ping', 'debug')
    SETTINGS['user_agent'] = conf.get('ping', 'user_agent')
    SETTINGS['socket_timeout'] = conf.getint('ping', 'socket_timeout')
    SETTINGS['cron_delay'] = conf.getint('ping', 'cron_delay')
    SETTINGS['crawl_dir'] = conf.get('ping', 'crawl_dir')
    if not os.path.exists(SETTINGS['crawl_dir']):
        os.makedirs(SETTINGS['crawl_dir'])
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
