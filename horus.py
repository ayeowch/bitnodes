#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# horus.py - Greenlets-based Bitcoin network pinger.
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
Greenlets-based Bitcoin network pinger.
"""

from gevent import monkey
monkey.patch_all()

import gevent
import gevent.pool
import json
import logging
import os
import redis
import redis.connection
import socket
import sys
from ConfigParser import ConfigParser

from protocol import ProtocolError, Connection

redis.connection.socket = gevent.socket

# Global instance of Redis connection
REDIS_CONN = redis.StrictRedis()

SETTINGS = {}


def keepalive(connection):
    """
    Periodically sends a ping message to the specified node to maintain open
    connection. All open connections are tracked in open set in Redis.
    """
    REDIS_CONN.sadd('open', connection.to_addr)

    while True:
        try:
            connection.ping()
        except socket.error as err:
            logging.debug("Closing {} ({})".format(connection.to_addr, err))
            break
        gevent.sleep(SETTINGS['keepalive_delay'])

    connection.close()
    REDIS_CONN.srem('open', connection.to_addr)


def task():
    """
    Assigned to a worker to retrieve (pop) a node from the reachable set and
    attempt to establish and maintain connection with the node.
    """
    node = REDIS_CONN.spop('reachable')
    (address, port, start_height) = eval(node)

    handshake_msgs = []
    connection = Connection((address, port),
                            socket_timeout=SETTINGS['socket_timeout'],
                            user_agent=SETTINGS['user_agent'],
                            start_height=start_height)
    try:
        connection.open()
        handshake_msgs = connection.handshake()
    except ProtocolError as err:
        connection.close()
    except socket.error as err:
        connection.close()

    if len(handshake_msgs) > 0:
        keepalive(connection)


def cron(pool):
    """
    Assigned to a worker to perform the following tasks periodically to
    maintain a continuous network-wide connections:
    1) Checks for a new snapshot
    2) Loads new reachable nodes into the reachable set in Redis
    3) Spawns workers to establish and maintain connection with reachable nodes
    """
    snapshot = None

    while True:
        workers = SETTINGS['workers'] - pool.free_count()
        logging.info("Workers: {}".format(workers))
        logging.info("Connections: {}".format(REDIS_CONN.scard('open')))

        new_snapshot = get_snapshot()
        if new_snapshot != snapshot:
            snapshot = new_snapshot
            logging.info("Snapshot: {}".format(snapshot))

            nodes = get_nodes(snapshot)
            logging.info("Nodes: {}".format(len(nodes)))

            reachable_nodes = set_reachable(nodes)
            logging.info("Reachable nodes: {}".format(reachable_nodes))

            for _ in xrange(reachable_nodes):
                pool.spawn(task)

        gevent.sleep(SETTINGS['cron_delay'])


def listdir(path):
    """
    Returns all but hidden files under the specified path.
    """
    for filename in os.listdir(path):
        if not filename.startswith('.'):
            yield filename


def get_snapshot():
    """
    Returns latest JSON file (based on creation date) containing a snapshot of
    all reachable nodes from a completed crawl.
    """
    snapshot = None
    ctime = lambda f: os.stat(os.path.join(SETTINGS['data'], f)).st_ctime
    files = sorted(listdir(SETTINGS['data']), key=ctime, reverse=True)
    if len(files) > 0:
        snapshot = os.path.join(SETTINGS['data'], files[0])
    return snapshot


def get_nodes(path):
    """
    Returns all reachable nodes from a JSON file.
    """
    text = open(path, 'r').read()
    nodes = json.loads(text)
    return nodes


def set_reachable(nodes):
    """
    Adds reachable nodes that are not already in the open set into the
    reachable set in Redis. New workers can be spawned separately to establish
    and maintain connection with these nodes.
    """
    redis_pipe = REDIS_CONN.pipeline()
    for node in nodes:
        address = str(node[0])
        port = int(node[1])
        start_height = int(node[-1])
        if not REDIS_CONN.sismember('open', (address, port)):
            redis_pipe.sadd('reachable', (address, port, start_height))
    redis_pipe.execute()
    return REDIS_CONN.scard('reachable')


def init_settings(argv):
    """
    Populates SETTINGS with key-value pairs from configuration file.
    """
    conf = ConfigParser()
    conf.read(argv[1])
    SETTINGS['logfile'] = conf.get('horus', 'logfile')
    SETTINGS['workers'] = conf.getint('horus', 'workers')
    SETTINGS['debug'] = conf.getboolean('horus', 'debug')
    SETTINGS['user_agent'] = conf.get('horus', 'user_agent')
    SETTINGS['socket_timeout'] = conf.getint('horus', 'socket_timeout')
    SETTINGS['cron_delay'] = conf.getint('horus', 'cron_delay')
    SETTINGS['keepalive_delay'] = conf.getint('horus', 'keepalive_delay')
    SETTINGS['data'] = conf.get('horus', 'data')


def main(argv):
    if len(argv) < 2 or not os.path.exists(argv[1]):
        print("Usage: horus.py [config]")
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
    REDIS_CONN.delete('reachable')
    REDIS_CONN.delete('open')

    # Initialize a pool of workers (greenlets)
    pool = gevent.pool.Pool(SETTINGS['workers'])
    pool.spawn(cron, pool)
    pool.join()

    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
