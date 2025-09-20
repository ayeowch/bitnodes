#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# ping.py - Greenlets-based Bitcoin network pinger.
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
Greenlets-based Bitcoin network pinger.
"""

from gevent import monkey

monkey.patch_all()

import glob
import json
import logging
import os
import random
import socket
import sys
import time
from configparser import ConfigParser
from ipaddress import ip_network

import gevent
import gevent.pool
import redis.connection
from binascii import hexlify, unhexlify

from protocol import Connection, ConnectionError, ONION_SUFFIX, ProtocolError
from utils import (
    conf_list,
    get_keys,
    http_get_txt,
    init_logger,
    ip_port_list,
    ip_to_network,
    new_redis_conn,
    txt_items,
)

redis.connection.socket = gevent.socket

CONF = {}


class Keepalive(object):
    """
    Implement keepalive mechanic to keep the specified connection with a node.
    """

    def __init__(self, conn=None, version_msg=None, redis_conn=None):
        self.conn = conn
        self.node = conn.to_addr

        self.start_time = int(time.time())
        self.last_ping = self.start_time
        self.last_version = self.start_time

        self.ping_delay = 60
        self.max_ping_delay = 600
        self.version_delay = CONF["version_delay"]

        self.redis_conn = redis_conn
        self.redis_pipe = redis_conn.pipeline()

        version = version_msg.get("version", "")
        user_agent = version_msg.get("user_agent", "")
        services = version_msg.get("services", "")

        # Open connections are tracked in open set with the associated data
        # stored in opendata set in Redis.
        self.data = self.node + (version, user_agent, self.start_time, services)
        self.redis_conn.zadd("opendata", {json.dumps(self.data): self.start_time})

    def keepalive(self):
        """
        Periodically send ping message and refresh version information.
        """
        while True:
            now = time.time()

            if now > self.last_ping + self.ping_delay:
                if not self.ping(now):
                    break

            if now > self.last_version + self.version_delay:
                self.version(now)

            if not self.sink():
                break

            gevent.sleep(0.1)

        self.close()

    def close(self):
        self.redis_conn.zrem("opendata", json.dumps(self.data))
        self.conn.close()

    def ping(self, now):
        """
        Send a ping message. Ping time is stored in Redis for round-trip time
        (RTT) calculation.
        """
        self.last_ping = now

        nonce = random.getrandbits(64)
        try:
            self.conn.ping(nonce=nonce)
        except socket.error as err:
            logging.debug("Closing %s (%s)", self.node, err)
            return False
        logging.debug("%s (%d)", self.node, nonce)

        key = f"ping:{self.node[0]}-{self.node[1]}:{nonce}"
        self.redis_conn.lpush(key, int(self.last_ping * 1000))  # milliseconds
        self.redis_conn.expire(key, CONF["rtt_ttl"])

        try:
            self.ping_delay = min(
                self.max_ping_delay,
                json.loads(self.redis_conn.lindex("elapsed", 0))[1],
            )
        except TypeError:
            pass

        # Refresh timestamp in opendata set.
        self.redis_conn.zadd("opendata", {json.dumps(self.data): int(now)})

        return True

    def version(self, now):
        """
        Refresh version information using response from latest handshake.
        """
        self.last_version = now

        version_key = f"version:{self.node[0]}-{self.node[1]}"
        version_data = self.redis_conn.get(version_key)
        if version_data is None:
            return

        version, user_agent, services = json.loads(version_data)
        if all([version, user_agent, services]):
            data = self.node + (version, user_agent, self.start_time, services)

            if self.data != data:
                self.redis_conn.zrem("opendata", json.dumps(self.data))
                self.redis_conn.zadd("opendata", {json.dumps(data): int(now)})
                self.data = data

    def sink(self):
        """
        Sink received messages to flush them off socket buffer.
        """
        try:
            msgs = self.conn.get_messages()
        except socket.timeout:
            pass
        except (ProtocolError, ConnectionError, socket.error) as err:
            logging.debug("Closing %s (%s)", self.node, err)
            return False
        else:
            # Cache block inv messages
            for msg in msgs:
                if msg["command"] != b"inv":
                    continue
                ms = msg["timestamp"]
                for inv in msg["inventory"]:
                    if inv["type"] != 2:
                        continue
                    key = f"binv:{inv['hash'].decode()}"
                    self.redis_pipe.execute_command(
                        "ZADD", key, "LT", ms, f"{self.node[0]}-{self.node[1]}"
                    )
                    self.redis_pipe.expire(key, CONF["inv_ttl"])
            self.redis_pipe.execute()

        return True


class ConnectionManager(object):
    """
    Implement handling of persistent connection to a reachable node.
    """

    def __init__(self, redis_conn=None):
        self.redis_conn = redis_conn

        self.address = None
        self.port = None
        self.services = None
        self.height = None

        self.node = None
        self.node_key = None

        self.relay = CONF["relay"]
        self.proxy = None

        self.cidr_key = None
        self.cidr_limit = None

        # Retrieve (pop) a node to connect to from the reachable set.
        if node := self.redis_conn.spop("reachable"):
            self.address, self.port, self.services, self.height = json.loads(node)
            self.node = (self.address, self.port)
            self.node_key = f"open:{self.address}-{self.port}"

            if self.address.endswith(ONION_SUFFIX) and CONF["onion"]:
                self.relay = CONF["onion_relay"]
                self.proxy = random.choice(CONF["tor_proxies"])

            self.init_cidr_limit()

    def init_cidr_limit(self):
        """
        Initialize prefix-level connection limit for the address.
        """
        if self.address.endswith(ONION_SUFFIX):
            return

        family = socket.AF_INET6 if ":" in self.address else socket.AF_INET
        addr = int(hexlify(socket.inet_pton(family, self.address)), 16)

        limit_tup = None
        if CONF["current_cidr_limits"]:
            limit_tup = next(
                (tup for tup in CONF["current_cidr_limits"] if addr & tup[1] == tup[0]),
                None,
            )

        if limit_tup is not None:
            net, mask, limit = limit_tup
            self.cidr_key = f"ping:cidr:{net}/{mask}"
            self.cidr_limit = limit
        elif ":" in self.address and CONF["ipv6_prefix"] < 128:
            cidr = ip_to_network(self.address, CONF["ipv6_prefix"])
            self.cidr_key = f"ping:cidr:{cidr}"
            self.cidr_limit = CONF["nodes_per_ipv6_prefix"]

    def increment_cidr_key(self):
        """
        Increment value of CIDR key in Redis.
        """
        nodes = self.redis_conn.incr(self.cidr_key)
        logging.debug("%s: %d", self.cidr_key, nodes)
        return nodes

    def decrement_cidr_key(self):
        """
        Decrement value of CIDR key in Redis.
        """
        nodes = self.redis_conn.decr(self.cidr_key)
        logging.debug("%s: %d", self.cidr_key, nodes)
        return nodes

    def is_allowed(self):
        """
        Return True if there are no restrictions to connect to the node,
        False if otherwise.
        """
        if self.node is None:
            return False

        if self.cidr_key:
            nodes = self.increment_cidr_key()
            if nodes > self.cidr_limit:
                logging.debug("CIDR limit reached: %s", self.node)
                self.decrement_cidr_key()
                return False

        if not self.redis_conn.set(self.node_key, int(time.time()), nx=True):
            logging.debug("Connection exists: %s", self.node)
            if self.cidr_key:
                self.decrement_cidr_key()
            return False

        return True

    def connect(self):
        """
        Establish and persist connection with the node.
        """
        if not self.is_allowed():
            return

        version_msg = {}
        conn = Connection(
            self.node,
            (
                (
                    CONF["ipv6_source_address"]
                    if ":" in self.address
                    else CONF["ipv4_source_address"]
                ),
                0,
            ),
            magic_number=CONF["magic_number"],
            socket_timeout=CONF["socket_timeout"],
            proxy=self.proxy,
            protocol_version=CONF["protocol_version"],
            to_services=self.services,
            from_services=CONF["services"],
            user_agent=CONF["user_agent"],
            height=self.height,
            relay=self.relay,
        )
        try:
            logging.debug("Connecting to %s", conn.to_addr)
            conn.open()
            version_msg = conn.handshake()
        except (ProtocolError, ConnectionError, socket.error) as err:
            logging.debug("Closing %s (%s)", self.node, err)
            conn.close()

        if not version_msg:
            if self.cidr_key:
                self.decrement_cidr_key()
            self.redis_conn.delete(self.node_key)
            return

        # Map local port to .onion node.
        if self.address.endswith(ONION_SUFFIX):
            local_port = conn.socket.getsockname()[1]
            remote_port = self.proxy[1]
            self.redis_conn.set(
                f"onion:{local_port}:{remote_port}", json.dumps(conn.to_addr)
            )

        Keepalive(
            conn=conn,
            version_msg=version_msg,
            redis_conn=self.redis_conn,
        ).keepalive()

        if self.cidr_key:
            self.decrement_cidr_key()
        self.redis_conn.delete(self.node_key)


def cron(pool, redis_conn):
    """
    Assigned to a worker to perform the following tasks periodically to
    maintain a continuous network-wide connections:

    [Master]
    1) Check for a new snapshot
    2) Load new reachable nodes into the reachable set in Redis
    3) Signal listener to get reachable nodes from opendata set

    [Master/Slave]
    1) Spawn workers to establish and maintain connection with reachable nodes
    """
    magic_number = hexlify(CONF["magic_number"]).decode()
    publish_key = f"snapshot:{magic_number}"
    snapshot = None

    while True:
        if CONF["master"]:
            new_snapshot = get_snapshot()

            if new_snapshot != snapshot:
                nodes = get_nodes(new_snapshot)
                if len(nodes) == 0:
                    continue

                # Remove stale entries from opendata set.
                redis_conn.zremrangebyscore("opendata", "-inf", int(time.time()) - 1200)

                logging.info("New snapshot: %s", new_snapshot)
                snapshot = new_snapshot

                logging.info("Nodes: %d", len(nodes))

                reachable_nodes = set_reachable(nodes, redis_conn)
                logging.info("New reachable nodes: %d", reachable_nodes)

                update_cidr_limits(redis_conn)

                # Allow connections to stabilize before publishing snapshot.
                gevent.sleep(CONF["socket_timeout"])
                redis_conn.publish(publish_key, int(time.time()))

        set_cidr_limits(redis_conn)

        for _ in range(min(redis_conn.scard("reachable"), pool.free_count())):
            pool.spawn(lambda: ConnectionManager(redis_conn).connect())

        workers = CONF["workers"] - pool.free_count()
        logging.debug("Workers: %d", workers)

        gevent.sleep(CONF["cron_delay"])


def get_snapshot():
    """
    Return latest JSON file (based on creation date) containing a snapshot of
    all reachable nodes from a completed crawl.
    """
    snapshot = None
    try:
        snapshot = max(glob.iglob(f"{CONF['crawl_dir']}/*.json"))
    except ValueError as err:
        logging.warning("%s", err)
    return snapshot


def get_nodes(path):
    """
    Return all reachable nodes from a JSON file.
    """
    nodes = []
    text = open(path, "r").read()
    try:
        nodes = json.loads(text)
    except ValueError as err:
        logging.warning("%s", err)
    return nodes


def set_reachable(nodes, redis_conn):
    """
    Add reachable nodes that are not already in the open set into the
    reachable set in Redis. New workers can be spawned separately to establish
    and maintain connection with these nodes.
    """
    for node in nodes:
        address = node[0]
        port = node[1]
        services = node[2]
        height = node[3]
        if not redis_conn.exists(f"open:{address}-{port}"):
            redis_conn.sadd("reachable", json.dumps((address, port, services, height)))
    return redis_conn.scard("reachable")


def set_cidr_limits(redis_conn):
    """
    Set latest CIDR limits from Redis in CONF.
    """
    cidr_limits = redis_conn.get("cidr-limits")
    if cidr_limits is not None:
        CONF["current_cidr_limits"] = {tuple(item) for item in json.loads(cidr_limits)}


def update_cidr_limits(redis_conn):
    """
    Update CIDR limits and store them in Redis.
    """
    if CONF["cidr_limits_from_url"]:
        txt = http_get_txt(CONF["cidr_limits_from_url"])
        cidr_limits = list_cidr_limits(txt_items(txt))
        if cidr_limits:
            logging.debug("CIDR limits: %d", len(cidr_limits))
            redis_conn.set("cidr-limits", json.dumps(list(cidr_limits)))


def list_cidr_limits(items):
    """
    Convert list of CIDRs and their associated limit into a list of tuples.
    """
    cidr_limits = set()
    for item in items:
        if "," in item:
            cidr, limit = item.split(",", 1)
            try:
                network = ip_network(cidr)
                limit = int(limit)
            except ValueError:
                continue
            else:
                cidr_limits.add(
                    (int(network.network_address), int(network.netmask), limit)
                )
    return cidr_limits


def init_conf(argv):
    """
    Populate CONF with key-value pairs from configuration file.
    """
    conf = ConfigParser()
    conf.read(argv[1])
    CONF["logfile"] = conf.get("ping", "logfile")
    CONF["magic_number"] = unhexlify(conf.get("ping", "magic_number"))
    CONF["db"] = conf.getint("ping", "db")
    CONF["workers"] = conf.getint("ping", "workers")
    CONF["debug"] = conf.getboolean("ping", "debug")
    CONF["ipv4_source_address"] = conf.get("ping", "ipv4_source_address")
    CONF["ipv6_source_address"] = conf.get("ping", "ipv6_source_address")
    CONF["protocol_version"] = conf.getint("ping", "protocol_version")
    CONF["user_agent"] = conf.get("ping", "user_agent")
    CONF["services"] = conf.getint("ping", "services")
    CONF["relay"] = conf.getint("ping", "relay")
    CONF["socket_timeout"] = conf.getint("ping", "socket_timeout")
    CONF["cron_delay"] = conf.getint("ping", "cron_delay")
    CONF["rtt_ttl"] = conf.getint("ping", "rtt_ttl")
    CONF["inv_ttl"] = conf.getint("ping", "inv_ttl")
    CONF["version_delay"] = conf.getint("ping", "version_delay")

    CONF["cidr_limits_from_url"] = conf.get("ping", "cidr_limits_from_url")
    CONF["current_cidr_limits"] = None
    CONF["ipv6_prefix"] = conf.getint("ping", "ipv6_prefix")
    CONF["nodes_per_ipv6_prefix"] = conf.getint("ping", "nodes_per_ipv6_prefix")

    CONF["onion"] = conf.getboolean("ping", "onion")
    CONF["tor_proxies"] = ip_port_list(conf_list(conf, "ping", "tor_proxies"))
    CONF["onion_relay"] = conf.getint("ping", "onion_relay")

    CONF["crawl_dir"] = conf.get("ping", "crawl_dir")
    if not os.path.exists(CONF["crawl_dir"]):
        os.makedirs(CONF["crawl_dir"])

    # Set to True for master process
    CONF["master"] = argv[2] == "master"


def main(argv):
    if len(argv) < 3 or not os.path.exists(argv[1]):
        print("Usage: ping.py [config] [master|slave]")
        return 1

    # Initialize global conf.
    init_conf(argv)

    # Initialize logger.
    init_logger(CONF["logfile"], debug=CONF["debug"], filemode="a")

    redis_conn = new_redis_conn(db=CONF["db"])

    if CONF["master"]:
        redis_pipe = redis_conn.pipeline()
        logging.info("Removing all keys")
        redis_pipe.delete("reachable")
        redis_pipe.delete("opendata")
        for key in get_keys(redis_conn, "open:*"):
            redis_pipe.delete(key)
        for key in get_keys(redis_conn, "ping:cidr:*"):
            redis_pipe.delete(key)
        redis_pipe.execute()

    # Initialize a pool of workers (greenlets).
    pool = gevent.pool.Pool(CONF["workers"])
    pool.spawn(cron, pool, redis_conn)
    pool.join()

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
