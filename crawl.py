#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# crawl.py - Greenlets-based Bitcoin network crawler.
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
Greenlets-based Bitcoin network crawler.
"""

from gevent import monkey

monkey.patch_all()

import json
import logging
import os
import random
import socket
import sys
import time
from configparser import ConfigParser
from functools import cache
from ipaddress import collapse_addresses, ip_address, ip_network

import geoip2.database
import gevent
import redis.connection
from binascii import hexlify, unhexlify
from geoip2.errors import AddressNotFoundError

from protocol import (
    CJDNS_NETWORK,
    Connection,
    ConnectionError,
    I2P_SUFFIX,
    ONION_SUFFIX,
    ProtocolError,
    TO_SERVICES,
)
from utils import (
    conf_list,
    conf_range,
    GeoIp,
    get_keys,
    http_get_txt,
    init_logger,
    ip_port_list,
    ip_to_network,
    new_redis_conn,
    throttle_run,
    txt_items,
)

redis.connection.socket = gevent.socket

CONF = {}

# MaxMind databases
ASN = geoip2.database.Reader(GeoIp.asn_db)


def getaddr(conn):
    """
    Send getaddr message.
    """
    addr_msgs = []
    try:
        conn.getaddr(block=False)
    except (ProtocolError, ConnectionError, socket.error) as err:
        logging.debug("%s: %s", conn.to_addr, err)
    else:
        addr_wait = 0
        while addr_wait < CONF["socket_timeout"]:
            addr_wait += 1
            gevent.sleep(0.3)
            try:
                msgs = conn.get_messages(commands=[b"addr", b"addrv2"])
            except (ProtocolError, ConnectionError, socket.error) as err:
                logging.debug("%s: %s", conn.to_addr, err)
                break
            if msgs and any([msg["count"] > 1 for msg in msgs]):
                addr_msgs = msgs
                break
    return addr_msgs


def get_peers(conn):
    """
    Return included peering nodes with age <= max. age.
    """
    now = int(time.time())
    peers = set()
    excluded_count = 0

    addr_msgs = getaddr(conn)

    for addr_msg in addr_msgs:
        if "addr_list" not in addr_msg:
            continue

        for peer in addr_msg["addr_list"]:
            timestamp = peer["timestamp"]
            age = now - timestamp  # seconds
            if age < 0 or age > CONF["current_max_age"]:
                continue
            address = (
                peer["ipv4"]
                or peer["ipv6"]
                or peer["onion"]
                or peer["i2p"]
                or peer["cjdns"]
            )
            port = peer["port"] if peer["port"] > 0 else CONF["port"]
            services = peer["services"]
            if not address:
                continue
            if is_excluded(address):
                logging.debug("Exclude: (%s, %d)", address, port)
                excluded_count += 1
                continue
            peers.add((address, port, services, timestamp))

    logging.debug(
        "%s Peers: %d (Excluded: %d)", conn.to_addr, len(peers), excluded_count
    )

    # Reject peers if hard limit is hit.
    if len(peers) > 1000:
        logging.debug("%s peers rejected", conn.to_addr)
        peers = set()
    peers = list(peers)[: CONF["peers_per_node"]]
    return peers


def get_cached_peers(conn, redis_conn):
    """
    Return cached peering nodes.
    """
    # Sample peers from .onion node at the specified sampling rate.
    if (
        conn.to_addr[0].endswith(ONION_SUFFIX)
        and hash(conn.to_addr[0]) % 100 >= CONF["onion_peers_sampling_rate"]
    ):
        return set()

    key = f"peer:{conn.to_addr[0]}-{conn.to_addr[1]}"
    peers = redis_conn.get(key)
    if peers:
        peers = json.loads(peers)
        logging.debug("%s Peers: %d", conn.to_addr, len(peers))
    else:
        peers = get_peers(conn)
        ttl = random.randrange(CONF["addr_ttl"][0], CONF["addr_ttl"][1] + 1)
        redis_conn.set(key, json.dumps(peers), ex=ttl)

    # Exclude timestamp from the tuples.
    peers = set(
        [(address, port, services) for (address, port, services, timestamp) in peers]
    )
    return peers


def set_version(address, port, version_msg, redis_pipe):
    """
    Store version information in Redis.
    """
    version = version_msg.get("version", "")
    user_agent = version_msg.get("user_agent", "")
    from_services = version_msg.get("services", 0)
    height = version_msg.get("height", 0)

    redis_pipe.set(
        f"height:{address}-{port}-{from_services}",
        height,
        ex=CONF["current_max_age"],
    )

    redis_pipe.set(
        f"version:{address}-{port}",
        json.dumps((version, user_agent, from_services)),
        ex=CONF["current_max_age"],
    )

    return from_services


def set_pending(conn, redis_conn, redis_pipe):
    """
    Add peering nodes to pending set.
    """
    peers = get_cached_peers(conn, redis_conn)
    for peer in peers:
        # I2P and CJDNS peers are cached but not crawled.
        address = peer[0]
        if address.endswith(I2P_SUFFIX):
            continue
        if not address.endswith(ONION_SUFFIX) and ip_address(address) in CJDNS_NETWORK:
            continue
        redis_pipe.sadd("pending", json.dumps(peer))


def connect(key, redis_conn):
    """
    Establish connection with a node to:
    1) Send version message
    2) Receive version and verack message
    3) Send getaddr message
    4) Receive addr message containing list of peering nodes
    """
    version_msg = {}

    redis_conn.set(key, "")  # Set Redis key for a new node.

    (address, port, services) = key[5:].split("-", 2)
    services = int(services)

    proxy = None
    if address.endswith(ONION_SUFFIX) and CONF["onion"]:
        proxy = random.choice(CONF["tor_proxies"])

    conn = Connection(
        (address, int(port)),
        (
            (
                CONF["ipv6_source_address"]
                if ":" in address
                else CONF["ipv4_source_address"]
            ),
            0,
        ),
        magic_number=CONF["magic_number"],
        socket_timeout=CONF["socket_timeout"],
        proxy=proxy,
        protocol_version=CONF["protocol_version"],
        to_services=services,
        from_services=CONF["services"],
        user_agent=CONF["user_agent"],
        height=CONF["height"],
        relay=CONF["relay"],
    )
    try:
        logging.debug("Connecting to %s (%d)", conn.to_addr, services)
        conn.open()
        version_msg = conn.handshake()
    except (ProtocolError, ConnectionError, socket.error) as err:
        logging.debug("%s: %s", conn.to_addr, err)

    if version_msg:
        redis_pipe = redis_conn.pipeline()
        from_services = set_version(address, port, version_msg, redis_pipe)
        if from_services != services:
            logging.debug(
                "%s Expected %d, got %d for services",
                conn.to_addr,
                services,
                from_services,
            )
            key = f"node:{address}-{port}-{from_services}"
        set_pending(conn, redis_conn, redis_pipe)
        redis_pipe.set(key, "")
        redis_pipe.sadd("up", key)
        redis_pipe.execute()

    conn.close()


def dump(timestamp, nodes, redis_conn):
    """
    Dump data for reachable nodes into timestamp-prefixed JSON file.
    """
    json_data = []

    logging.info("Building JSON data")
    for node in nodes:
        (address, port, services) = node.decode()[5:].split("-", 2)
        if is_excluded(address):
            logging.debug("Exclude: %s", address)
            continue
        height_key = f"height:{address}-{port}-{services}"
        try:
            height = int(redis_conn.get(height_key))
        except TypeError:
            logging.warning("%s missing", height_key)
            height = 0
        json_data.append([address, int(port), int(services), height])
    logging.info("Built JSON data: %d", len(json_data))

    if len(json_data) == 0:
        logging.warning("len(json_data): %d", len(json_data))
        return 0

    json_output = os.path.join(CONF["crawl_dir"], f"{timestamp}.json")
    open(json_output, "w").write(json.dumps(json_data))
    logging.info("Wrote %s", json_output)


def restart(timestamp, redis_conn):
    """
    Remove keys for all nodes from current crawl.
    Load reachable and checked nodes from Redis into next crawl set.
    Update number of reachable nodes in Redis.
    Dump data for the reachable nodes into a JSON file.
    """
    redis_pipe = redis_conn.pipeline()

    nodes = redis_conn.smembers("up")  # Reachable nodes.
    redis_pipe.delete("up")

    for key in get_keys(redis_conn, "node:*"):
        redis_pipe.delete(key)

    for key in get_keys(redis_conn, "crawl:cidr:*"):
        redis_pipe.delete(key)

    for node in nodes:
        (address, port, services) = node.decode()[5:].split("-", 2)
        if is_excluded(address):
            logging.debug("Exclude: %s", address)
            continue
        redis_pipe.sadd("pending", json.dumps((address, int(port), int(services))))

    if CONF["include_checked"]:
        checked_nodes = redis_conn.zrangebyscore(
            "check",
            timestamp - CONF["current_max_age"],
            timestamp,
        )
        for node in checked_nodes:
            (address, port, services) = json.loads(node)
            if is_excluded(address):
                logging.debug("Exclude: %s", address)
                continue
            redis_pipe.sadd("pending", json.dumps((address, port, services)))

    redis_pipe.execute()

    reachable_nodes = len(nodes)
    logging.info("Reachable nodes: %d", reachable_nodes)
    redis_conn.lpush("nodes", json.dumps((timestamp, reachable_nodes)))
    dump(timestamp, nodes, redis_conn)


def cron(redis_conn):
    """
    Assigned to a worker to perform the following tasks periodically to
    maintain a continuous crawl:
    1) Report the current number of nodes in crawl set
    2) Initiate a new crawl once the crawl set is empty
    """
    start = int(time.time())

    while True:
        pending = redis_conn.scard("pending")
        up = redis_conn.scard("up")
        logging.info("%d/%d", pending, up)

        if pending == 0:
            redis_conn.set("crawl:master:state", "starting")
            now = int(time.time())
            elapsed = now - start
            redis_conn.lpush("elapsed", json.dumps((now, elapsed)))
            logging.info("Elapsed: %d", elapsed)
            restart(now, redis_conn)
            while int(time.time()) - start < CONF["snapshot_delay"]:
                gevent.sleep(1)
            start = int(time.time())
            redis_conn.set("crawl:master:state", "running")

        gevent.sleep(CONF["cron_delay"])


def task(id, redis_conn):
    """
    Assigned to a worker to retrieve (pop) a node from the crawl set and
    attempt to establish connection with a new node.
    """
    while True:
        if id == 0:  # First worker only.
            reset_rules(redis_conn)

        # Skip if restart is in progress.
        if redis_conn.get("crawl:master:state") != b"running":
            gevent.sleep(1)
            continue

        # Skip if process-level cache is not ready.
        if CONF["cache_version"] == 0:
            gevent.sleep(1)
            continue

        node = redis_conn.spop("pending")  # Pop random node from set.
        if node is None:
            gevent.sleep(1)
            continue

        node = json.loads(node)

        # Skip IPv6 node.
        if ":" in node[0] and not CONF["ipv6"]:
            continue

        # Skip .onion node.
        if node[0].endswith(ONION_SUFFIX) and not CONF["onion"]:
            continue

        key = f"node:{node[0]}-{node[1]}-{node[2]}"
        if redis_conn.exists(key):
            continue

        # Check if prefix has hit its limit.
        if ":" in node[0] and CONF["ipv6_prefix"] < 128:
            cidr = ip_to_network(node[0], CONF["ipv6_prefix"])
            nodes = redis_conn.incr(f"crawl:cidr:{cidr}")
            if nodes > CONF["nodes_per_ipv6_prefix"]:
                logging.debug("CIDR %s: %d", cidr, nodes)
                continue

        connect(key, redis_conn)


def init_pending(redis_conn):
    """
    Initialize pending set in Redis with a list of reachable nodes from DNS
    seeders and hardcoded list of .onion nodes to bootstrap the crawler.
    """
    for seeder in CONF["seeders"]:
        nodes = set()

        try:
            ipv4_nodes = socket.getaddrinfo(seeder, None, socket.AF_INET)
        except socket.gaierror as err:
            logging.warning("%s", err)
        else:
            nodes.update([node[-1][0] for node in ipv4_nodes])

        if CONF["ipv6"]:
            try:
                ipv6_nodes = socket.getaddrinfo(seeder, None, socket.AF_INET6)
            except socket.gaierror as err:
                logging.warning("%s", err)
            else:
                nodes.update([node[-1][0] for node in ipv6_nodes])

        for node in nodes:
            if is_excluded(node):
                logging.debug("Exclude: %s", node)
                continue
            logging.debug("%s: %s", seeder, node)
            redis_conn.sadd("pending", json.dumps((node, CONF["port"], TO_SERVICES)))

    if CONF["onion"]:
        for node in CONF["onion_nodes"]:
            redis_conn.sadd("pending", json.dumps((node, CONF["port"], TO_SERVICES)))


@throttle_run(ttl=lambda: CONF["snapshot_delay"])
def reset_rules(redis_conn):
    """
    Reset process-level rules and cache at the start of a new crawl.
    """
    set_max_age(redis_conn)

    set_height(redis_conn)

    if CONF["master"]:
        update_included_asns(redis_conn)
        update_excluded_networks(redis_conn)
        update_excluded_nodes(redis_conn)
    else:
        set_included_asns(redis_conn)
        set_excluded_networks(redis_conn)
        set_excluded_nodes(redis_conn)

    cache_clear()


@throttle_run(ttl=lambda: random.randint(*CONF["cache_ttl"]))
def cache_clear():
    """
    Clear stale process-level cache.
    """
    logging.debug("Old cache stats: %s", is_excluded.cache_info())
    is_excluded.cache_clear()
    CONF["cache_version"] += 1
    logging.info("Cache version: %d", CONF["cache_version"])


@cache
def is_excluded(address):
    """
    Return True if address is found in exclusion rules, False if otherwise.

    In priority order, the rules are:
    - Exclude if address is in exclude_nodes
    - Include onion address
    - Include I2P address
    - Include CJDNS address
    - Exclude private address
    - Exclude address without ASN when include_asns/exclude_asns is set
    - Exclude if address is in exclude_asns
    - Exclude bad address
    - Exclude if address is in exclude_ipv4_networks/exclude_ipv6_networks
    - Exclude if address is not in include_asns
    - Include address
    """
    if address in CONF["current_exclude_nodes"]:
        return True

    if address.endswith(ONION_SUFFIX):
        return False

    if address.endswith(I2P_SUFFIX):
        return False

    ip_obj = ip_address(address)

    if ip_obj in CJDNS_NETWORK:
        return False

    if ip_obj.is_private:
        return True

    include_asns = CONF["current_include_asns"]
    exclude_asns = CONF["exclude_asns"]

    asn = None
    if include_asns or exclude_asns:
        try:
            asn_record = ASN.asn(address)
        except AddressNotFoundError:
            asn = None
        else:
            asn = asn_record.autonomous_system_number
        if asn is None:
            return True

    if asn in exclude_asns:
        return True

    if ":" in address:
        address_family = socket.AF_INET6
        exclude_ip_networks = CONF["current_exclude_ipv6_networks"]
    else:
        address_family = socket.AF_INET
        exclude_ip_networks = CONF["current_exclude_ipv4_networks"]
    try:
        addr = int(hexlify(socket.inet_pton(address_family, address)), 16)
    except socket.error:
        logging.warning("Bad address: %s", address)
        return True
    if any([(addr & net[1] == net[0]) for net in exclude_ip_networks]):
        return True

    if asn not in include_asns:
        return True

    return False


def set_max_age(redis_conn):
    """
    Adjust current max. age for peers to match the desired elapsed time.
    """
    elapsed_times = [
        json.loads(elapsed)[1] for elapsed in redis_conn.lrange("elapsed", 0, 18)
    ]
    if not elapsed_times:
        return

    avg_elapsed = int(sum(elapsed_times) / len(elapsed_times))

    prev_max_age = CONF["current_max_age"]

    new_max_age = int(
        max(
            CONF["max_age"][0],  # Min. value.
            min(
                CONF["max_age"][-1],  # Max. value.
                prev_max_age * (CONF["snapshot_delay"] / avg_elapsed),
            ),
        )
    )
    CONF["current_max_age"] = new_max_age
    logging.info("%d", CONF["current_max_age"])


def set_height(redis_conn):
    """
    Set latest consensus height from Redis in CONF.
    """
    height = redis_conn.get("height")
    if height is not None:
        CONF["height"] = int(height)
        logging.info("%d", CONF["height"])


def set_included_asns(redis_conn):
    """
    Set latest included ASNs from Redis in CONF.
    """
    asns = redis_conn.get("include-asns")
    if asns is not None:
        CONF["current_include_asns"] = set(json.loads(asns))


def update_included_asns(redis_conn):
    """
    Update included ASNs and store them Redis.
    """
    include_asns = set()

    if CONF["include_asns"]:
        include_asns.update(CONF["include_asns"])

    if CONF["include_asns_from_url"]:
        txt = http_get_txt(CONF["include_asns_from_url"])
        include_asns.update(txt_items(txt, func=int))

    logging.info("ASNs: %d", len(include_asns))
    redis_conn.set("include-asns", json.dumps(list(include_asns)))
    set_included_asns(redis_conn)


def set_excluded_networks(redis_conn):
    """
    Set latest excluded networks from Redis in CONF.
    """
    exclude_ipv4_networks = redis_conn.get("exclude-ipv4-networks")
    if exclude_ipv4_networks is not None:
        CONF["current_exclude_ipv4_networks"] = {
            tuple(item) for item in json.loads(exclude_ipv4_networks)
        }

    exclude_ipv6_networks = redis_conn.get("exclude-ipv6-networks")
    if exclude_ipv6_networks is not None:
        CONF["current_exclude_ipv6_networks"] = {
            tuple(item) for item in json.loads(exclude_ipv6_networks)
        }


def update_excluded_networks(redis_conn):
    """
    Update excluded networks and store them in Redis.
    """
    v4 = CONF["exclude_ipv4_networks"]
    v6 = CONF["exclude_ipv6_networks"]

    if CONF["exclude_ipv4_bogons_from_urls"]:
        for url in CONF["exclude_ipv4_bogons_from_urls"]:
            v4 = list_excluded_networks(txt_items(http_get_txt(url)), v4)

    if CONF["exclude_ipv6_bogons_from_urls"]:
        for url in CONF["exclude_ipv6_bogons_from_urls"]:
            v6 = list_excluded_networks(txt_items(http_get_txt(url)), v6)

    if CONF["exclude_ipv4_networks_from_url"]:
        url = CONF["exclude_ipv4_networks_from_url"]
        v4 = list_excluded_networks(txt_items(http_get_txt(url)), v4)

    if CONF["exclude_ipv6_networks_from_url"]:
        url = CONF["exclude_ipv6_networks_from_url"]
        v6 = list_excluded_networks(txt_items(http_get_txt(url)), v6)

    logging.info("IPv4: %d, IPv6: %d", len(v4), len(v6))
    redis_conn.set("exclude-ipv4-networks", json.dumps(list(v4)))
    redis_conn.set("exclude-ipv6-networks", json.dumps(list(v6)))
    set_excluded_networks(redis_conn)


def list_excluded_networks(items, existing_networks=None):
    """
    Convert list of networks into a list of tuples of network address and
    netmask to be excluded from the crawl.
    """
    networks = []

    if existing_networks:
        for net in existing_networks:
            networks.append(
                ip_network(f"{ip_address(net[0])}/{bin(net[1]).count('1')}")
            )

    for item in items:
        try:
            networks.append(ip_network(item))
        except ValueError:
            continue

    return set(
        (int(net.network_address), int(net.netmask))
        for net in collapse_addresses(networks)
    )


def set_excluded_nodes(redis_conn):
    """
    Set latest excluded nodes from Redis in CONF.
    """
    nodes = redis_conn.get("exclude-nodes")
    if nodes is not None:
        CONF["current_exclude_nodes"] = set(json.loads(nodes))


def update_excluded_nodes(redis_conn):
    """
    Update excluded nodes and store them Redis.
    """
    exclude_nodes = set()

    if CONF["exclude_nodes"]:
        exclude_nodes.update(CONF["exclude_nodes"])

    if CONF["exclude_nodes_from_url"]:
        txt = http_get_txt(CONF["exclude_nodes_from_url"])
        exclude_nodes.update(txt_items(txt))

    logging.info("Nodes: %d", len(exclude_nodes))
    redis_conn.set("exclude-nodes", json.dumps(list(exclude_nodes)))
    set_excluded_nodes(redis_conn)


def init_conf(argv):
    """
    Populate CONF with key-value pairs from configuration file.
    """
    conf = ConfigParser()
    conf.read(argv[1])
    CONF["logfile"] = conf.get("crawl", "logfile")
    CONF["magic_number"] = unhexlify(conf.get("crawl", "magic_number"))
    CONF["port"] = conf.getint("crawl", "port")
    CONF["db"] = conf.getint("crawl", "db")
    CONF["seeders"] = conf.get("crawl", "seeders").strip().split("\n")
    CONF["workers"] = conf.getint("crawl", "workers")
    CONF["debug"] = conf.getboolean("crawl", "debug")
    CONF["ipv4_source_address"] = conf.get("crawl", "ipv4_source_address")
    CONF["ipv6_source_address"] = conf.get("crawl", "ipv6_source_address")
    CONF["protocol_version"] = conf.getint("crawl", "protocol_version")
    CONF["user_agent"] = conf.get("crawl", "user_agent")
    CONF["services"] = conf.getint("crawl", "services")
    CONF["relay"] = conf.getint("crawl", "relay")
    CONF["socket_timeout"] = conf.getint("crawl", "socket_timeout")
    CONF["cron_delay"] = conf.getint("crawl", "cron_delay")
    CONF["snapshot_delay"] = conf.getint("crawl", "snapshot_delay")
    CONF["addr_ttl"] = conf_range(conf, "crawl", "addr_ttl")
    CONF["cache_ttl"] = conf_range(conf, "crawl", "cache_ttl")
    CONF["max_age"] = conf_range(conf, "crawl", "max_age")
    CONF["current_max_age"] = CONF["max_age"][-1]  # Max. value.
    CONF["peers_per_node"] = conf.getint("crawl", "peers_per_node")
    CONF["onion_peers_sampling_rate"] = conf.getint(
        "crawl", "onion_peers_sampling_rate"
    )
    CONF["ipv6"] = conf.getboolean("crawl", "ipv6")
    CONF["ipv6_prefix"] = conf.getint("crawl", "ipv6_prefix")
    CONF["nodes_per_ipv6_prefix"] = conf.getint("crawl", "nodes_per_ipv6_prefix")

    CONF["include_asns"] = conf_list(conf, "crawl", "include_asns", func=int)
    CONF["include_asns_from_url"] = conf.get("crawl", "include_asns_from_url")
    CONF["current_include_asns"] = set()

    CONF["exclude_asns"] = conf_list(conf, "crawl", "exclude_asns", func=int)

    CONF["exclude_ipv4_networks"] = list_excluded_networks(
        conf_list(conf, "crawl", "exclude_ipv4_networks")
    )
    CONF["exclude_ipv6_networks"] = list_excluded_networks(
        conf_list(conf, "crawl", "exclude_ipv6_networks")
    )

    CONF["exclude_ipv4_bogons_from_urls"] = conf_list(
        conf, "crawl", "exclude_ipv4_bogons_from_urls"
    )
    CONF["exclude_ipv6_bogons_from_urls"] = conf_list(
        conf, "crawl", "exclude_ipv6_bogons_from_urls"
    )

    CONF["exclude_ipv4_networks_from_url"] = conf.get(
        "crawl", "exclude_ipv4_networks_from_url"
    )
    CONF["exclude_ipv6_networks_from_url"] = conf.get(
        "crawl", "exclude_ipv6_networks_from_url"
    )

    CONF["current_exclude_ipv4_networks"] = set()
    CONF["current_exclude_ipv6_networks"] = set()

    CONF["exclude_nodes"] = conf_list(conf, "crawl", "exclude_nodes")
    CONF["exclude_nodes_from_url"] = conf.get("crawl", "exclude_nodes_from_url")
    CONF["current_exclude_nodes"] = set()

    CONF["onion"] = conf.getboolean("crawl", "onion")
    CONF["tor_proxies"] = ip_port_list(conf_list(conf, "crawl", "tor_proxies"))
    CONF["onion_nodes"] = conf_list(conf, "crawl", "onion_nodes")

    CONF["include_checked"] = conf.getboolean("crawl", "include_checked")

    CONF["crawl_dir"] = conf.get("crawl", "crawl_dir")
    if not os.path.exists(CONF["crawl_dir"]):
        os.makedirs(CONF["crawl_dir"])

    # Set to True for master process.
    CONF["master"] = argv[2] == "master"

    # Version tracking for process-level cache.
    CONF["cache_version"] = 0

    # Consensus height.
    CONF["height"] = None


def main(argv):
    if len(argv) < 3 or not os.path.exists(argv[1]):
        print("Usage: crawl.py [config] [master|slave]")
        return 1

    # Initialize global conf.
    init_conf(argv)

    # Initialize logger.
    init_logger(CONF["logfile"], debug=CONF["debug"], filemode="a")

    redis_conn = new_redis_conn(db=CONF["db"])

    if CONF["master"]:
        redis_conn.set("crawl:master:state", "starting")
        logging.info("Removing all keys")
        redis_pipe = redis_conn.pipeline()
        redis_pipe.delete("up")
        patterns = [
            "crawl:cidr:*",
            "height:*",
            "node:*",
            "peer:*",
            "version:*",
        ]
        for pattern in patterns:
            for key in get_keys(redis_conn, pattern):
                redis_pipe.delete(key)
        redis_pipe.delete("pending")
        redis_pipe.execute()
        reset_rules(redis_conn)
        init_pending(redis_conn)
        redis_conn.set("crawl:master:state", "running")

    # Spawn workers (greenlets) including one worker reserved for cron tasks.
    workers = []
    if CONF["master"]:
        workers.append(gevent.spawn(cron, redis_conn))
    for id in range(CONF["workers"] - len(workers)):
        workers.append(gevent.spawn(task, id, redis_conn))
    logging.info("Workers: %d", len(workers))
    gevent.joinall(workers)

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
