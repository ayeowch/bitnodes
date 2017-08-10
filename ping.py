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
from binascii import hexlify, unhexlify
from ConfigParser import ConfigParser

from protocol import ProtocolError, ConnectionError, Connection
from utils import new_redis_conn, get_keys, ip_to_network

redis.connection.socket = gevent.socket

REDIS_CONN = None
CONF = {}


class Keepalive(object):
    """
    Implements keepalive mechanic to keep the specified connection with a node.
    """
    def __init__(self, conn, version_msg):
        self.conn = conn
        self.node = conn.to_addr
        self.version_msg = version_msg
        self.last_ping = int(time.time())
        self.keepalive_time = 60
        self.last_bestblockhash = None

    def keepalive(self):
        """
        Periodically sends the following messages:
        1) ping message
        2) inv message for the consensus block
        3) addr message containing a subset of the reachable nodes
        Open connections are tracked in open set with the associated data
        stored in opendata set in Redis.
        """
        version = self.version_msg.get('version', "")
        user_agent = self.version_msg.get('user_agent', "")
        services = self.version_msg.get('services', "")
        data = self.node + (version, user_agent, self.last_ping, services)

        REDIS_CONN.sadd('opendata', data)

        while True:
            if time.time() > self.last_ping + self.keepalive_time:
                try:
                    self.ping()
                except socket.error as err:
                    logging.info("ping: Closing %s (%s)", self.node, err)
                    break

                try:
                    self.send_bestblockhash()
                except socket.error as err:
                    logging.info(
                        "send_bestblockhash: Closing %s (%s)", self.node, err)
                    break

                try:
                    self.send_addr()
                except socket.error as err:
                    logging.info("send_addr: Closing %s (%s)", self.node, err)
                    break

            # Sink received messages to flush them off socket buffer
            try:
                self.conn.get_messages()
            except socket.timeout:
                pass
            except (ProtocolError, ConnectionError, socket.error) as err:
                logging.info("get_messages: Closing %s (%s)", self.node, err)
                break
            gevent.sleep(0.3)

        REDIS_CONN.srem('opendata', data)

    def ping(self):
        """
        Sends a ping message. Ping time is stored in Redis for round-trip time
        (RTT) calculation.
        """
        nonce = random.getrandbits(64)
        try:
            self.conn.ping(nonce=nonce)
        except socket.error:
            raise
        logging.debug("%s (%s)", self.node, nonce)

        self.last_ping = time.time()
        key = "ping:{}-{}:{}".format(self.node[0], self.node[1], nonce)
        REDIS_CONN.lpush(key, int(self.last_ping * 1000))  # in ms
        REDIS_CONN.expire(key, CONF['ttl'])

        try:
            self.keepalive_time = int(REDIS_CONN.get('elapsed'))
        except TypeError:
            pass

    def send_bestblockhash(self):
        """
        Sends an inv message for the consensus block.
        """
        bestblockhash = REDIS_CONN.get('bestblockhash')
        if self.last_bestblockhash == bestblockhash:
            return
        try:
            self.conn.inv(inventory=[(2, bestblockhash)])
        except socket.error:
            raise
        logging.debug("%s (%s)", self.node, bestblockhash)
        self.last_bestblockhash = bestblockhash

    def send_addr(self):
        """
        Sends an addr message containing a subset of the reachable nodes.
        """
        nodes = REDIS_CONN.srandmember('opendata', 10)
        nodes = [eval(node) for node in nodes]
        addr_list = []
        timestamp = int(self.last_ping)  # Timestamp less than 10 minutes old
        for node in nodes:
            # address, port, version, user_agent, timestamp, services
            address = node[0]
            port = node[1]
            services = node[-1]
            if address == self.node[0]:
                continue
            if not services & 1 == 1:  # Skip if not NODE_NETWORK
                continue
            addr_list.append((timestamp, services, address, port))
        if len(addr_list) == 0:
            return
        try:
            self.conn.addr(addr_list=addr_list)
        except socket.error:
            raise
        logging.debug("%s (%s)", self.node, addr_list)


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

    # Check if prefix has hit its limit
    cidr_key = None
    if ":" in address and CONF['ipv6_prefix'] < 128:
        cidr = ip_to_network(address, CONF['ipv6_prefix'])
        cidr_key = 'ping:cidr:{}'.format(cidr)
        nodes = REDIS_CONN.incr(cidr_key)
        logging.info("+CIDR %s: %d", cidr, nodes)
        if nodes > CONF['nodes_per_ipv6_prefix']:
            logging.info("CIDR limit reached: %s", cidr)
            nodes = REDIS_CONN.decr(cidr_key)
            logging.info("-CIDR %s: %d", cidr, nodes)
            return

    if REDIS_CONN.sadd('open', node) == 0:
        logging.info("Connection exists: %s", node)
        if cidr_key:
            nodes = REDIS_CONN.decr(cidr_key)
            logging.info("-CIDR %s: %d", cidr, nodes)
        return

    proxy = None
    if address.endswith(".onion"):
        proxy = CONF['tor_proxy']

    handshake_msgs = []
    conn = Connection(node,
                      (CONF['source_address'], 0),
                      magic_number=CONF['magic_number'],
                      socket_timeout=CONF['socket_timeout'],
                      proxy=proxy,
                      protocol_version=CONF['protocol_version'],
                      to_services=services,
                      from_services=CONF['services'],
                      user_agent=CONF['user_agent'],
                      height=height,
                      relay=CONF['relay'])
    try:
        logging.debug("Connecting to %s", conn.to_addr)
        conn.open()
        handshake_msgs = conn.handshake()
    except (ProtocolError, ConnectionError, socket.error) as err:
        logging.debug("Closing %s (%s)", node, err)
        conn.close()

    if len(handshake_msgs) == 0:
        if cidr_key:
            nodes = REDIS_CONN.decr(cidr_key)
            logging.info("-CIDR %s: %d", cidr, nodes)
        REDIS_CONN.srem('open', node)
        return

    if address.endswith(".onion"):
        # Map local port to .onion node
        local_port = conn.socket.getsockname()[1]
        logging.info("%s: 127.0.0.1:%d", conn.to_addr, local_port)
        REDIS_CONN.set('onion:{}'.format(local_port), conn.to_addr)

    Keepalive(conn=conn, version_msg=handshake_msgs[0]).keepalive()
    conn.close()
    if cidr_key:
        nodes = REDIS_CONN.decr(cidr_key)
        logging.info("-CIDR %s: %d", cidr, nodes)
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
    publish_key = 'snapshot:{}'.format(hexlify(CONF['magic_number']))
    snapshot = None

    while True:
        if CONF['master']:
            new_snapshot = get_snapshot()

            if new_snapshot != snapshot:
                nodes = get_nodes(new_snapshot)
                if len(nodes) == 0:
                    continue

                logging.info("New snapshot: %s", new_snapshot)
                snapshot = new_snapshot

                logging.info("Nodes: %d", len(nodes))

                reachable_nodes = set_reachable(nodes)
                logging.info("New reachable nodes: %d", reachable_nodes)

                # Allow connections to stabilize before publishing snapshot
                gevent.sleep(CONF['socket_timeout'])
                REDIS_CONN.publish(publish_key, int(time.time()))

            connections = REDIS_CONN.scard('open')
            logging.info("Connections: %d", connections)

            set_bestblockhash()

        for _ in xrange(min(REDIS_CONN.scard('reachable'), pool.free_count())):
            pool.spawn(task)

        workers = CONF['workers'] - pool.free_count()
        logging.info("Workers: %d", workers)

        gevent.sleep(CONF['cron_delay'])


def get_snapshot():
    """
    Returns latest JSON file (based on creation date) containing a snapshot of
    all reachable nodes from a completed crawl.
    """
    snapshot = None
    try:
        snapshot = max(glob.iglob("{}/*.json".format(CONF['crawl_dir'])))
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
        logging.info("bestblockhash: %s", lastblockhash)


def init_conf(argv):
    """
    Populates CONF with key-value pairs from configuration file.
    """
    conf = ConfigParser()
    conf.read(argv[1])
    CONF['logfile'] = conf.get('ping', 'logfile')
    CONF['magic_number'] = unhexlify(conf.get('ping', 'magic_number'))
    CONF['db'] = conf.getint('ping', 'db')
    CONF['workers'] = conf.getint('ping', 'workers')
    CONF['debug'] = conf.getboolean('ping', 'debug')
    CONF['source_address'] = conf.get('ping', 'source_address')
    CONF['protocol_version'] = conf.getint('ping', 'protocol_version')
    CONF['user_agent'] = conf.get('ping', 'user_agent')
    CONF['services'] = conf.getint('ping', 'services')
    CONF['relay'] = conf.getint('ping', 'relay')
    CONF['socket_timeout'] = conf.getint('ping', 'socket_timeout')
    CONF['cron_delay'] = conf.getint('ping', 'cron_delay')
    CONF['ttl'] = conf.getint('ping', 'ttl')
    CONF['ipv6_prefix'] = conf.getint('ping', 'ipv6_prefix')
    CONF['nodes_per_ipv6_prefix'] = conf.getint('ping',
                                                'nodes_per_ipv6_prefix')

    CONF['onion'] = conf.getboolean('ping', 'onion')
    CONF['tor_proxy'] = None
    if CONF['onion']:
        tor_proxy = conf.get('ping', 'tor_proxy').split(":")
        CONF['tor_proxy'] = (tor_proxy[0], int(tor_proxy[1]))

    CONF['crawl_dir'] = conf.get('ping', 'crawl_dir')
    if not os.path.exists(CONF['crawl_dir']):
        os.makedirs(CONF['crawl_dir'])

    # Set to True for master process
    CONF['master'] = argv[2] == "master"


def main(argv):
    if len(argv) < 3 or not os.path.exists(argv[1]):
        print("Usage: ping.py [config] [master|slave]")
        return 1

    # Initialize global conf
    init_conf(argv)

    # Initialize logger
    loglevel = logging.INFO
    if CONF['debug']:
        loglevel = logging.DEBUG

    logformat = ("[%(process)d] %(asctime)s,%(msecs)05.1f %(levelname)s "
                 "(%(funcName)s) %(message)s")
    logging.basicConfig(level=loglevel,
                        format=logformat,
                        filename=CONF['logfile'],
                        filemode='a')
    print("Log: {}, press CTRL+C to terminate..".format(CONF['logfile']))

    global REDIS_CONN
    REDIS_CONN = new_redis_conn(db=CONF['db'])

    if CONF['master']:
        redis_pipe = REDIS_CONN.pipeline()
        logging.info("Removing all keys")
        redis_pipe.delete('reachable')
        redis_pipe.delete('open')
        redis_pipe.delete('opendata')
        for key in get_keys(REDIS_CONN, 'ping:cidr:*'):
            redis_pipe.delete(key)
        redis_pipe.execute()

    # Initialize a pool of workers (greenlets)
    pool = gevent.pool.Pool(CONF['workers'])
    pool.spawn(cron, pool)
    pool.join()

    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
