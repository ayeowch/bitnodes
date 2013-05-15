#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# bitnodes.py - Recursively get all connected Bitcoin nodes.
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
Recursively get all connected Bitcoin nodes.
"""
__version__ = '0.1'

import datetime
import json
import logging
import os
import random
import re
import socket
import sqlite3
import sys
import time
import urllib2
from ConfigParser import ConfigParser
from multiprocessing import Pool
from subprocess import Popen, PIPE

from protocol import ProtocolError, Connection
from tests import DUMMY_SEEDS, dummy_getaddr

DEFAULT_PORT = 8333
SETTINGS = {}


def execute_cmd(cmd):
    """
    Executes given command using subprocess.Popen().
    """
    msg = "[{}]".format(cmd)
    logging.debug(msg)

    process = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    stdout, stderr = process.communicate()
    returncode = process.returncode
    if returncode != 0:
        msg = "{} failed: {}".format(cmd, stderr)
        logging.warning(msg)
        raise RuntimeError(msg)

    return stdout


def dig(ip_address):
    """
    Performs DNS lookup against the given IP address using dig.
    """
    cmd = "{} +short {}".format(SETTINGS['dig'], ip_address)
    try:
        stdout = execute_cmd(cmd)
    except RuntimeError:
        return ""
    return stdout


def urlopen(url):
    """
    Fetches webpage.
    """
    response = ''
    request = urllib2.Request(url=url)

    try:
        response = urllib2.urlopen(request).read()
    except urllib2.HTTPError, err:
        logging.warning("HTTPError: {} ({})".format(url, err.code))
    except urllib2.URLError, err:
        logging.warning("URLError: {} ({})".format(url, err.reason))

    return response


def status():
    """
    Logs the number of nodes found so far on a periodical basis.
    """
    current = 0
    last = 0
    database = Database(database=SETTINGS['database'])

    while True:
        time.sleep(SETTINGS['status_interval'])
        current = database.count_nodes()

        # Stop reporting if no more changes
        if current == last:
            logging.debug("status() stopped, {} == {}".format(current, last))
            break

        logging.info("Found {} nodes".format(current))
        last = current

    database.close()


class KeyboardInterruptError(Exception):
    """
    Changes KeyboardInterrupt exception caught by a pool worker into an
    exception that inherits Exception so that parent process can pick up
    KeyboardInterrupt exception and handle it accordingly.
    """
    pass


def job(seed):
    """
    A worker function; each worker is given a seed node to begin with to
    get all adjacent nodes recursively.
    seed with tuple (0, 'stat') is reserved for periodical status reporting.
    """
    if seed[1] == "stat":
        try:
            status()
        except KeyboardInterrupt:
            raise KeyboardInterruptError

    else:
        msg = "Started job({})".format(seed)
        logging.debug(msg)

        try:
            network = Network(seed=seed)
            network.traverse_network()
        except KeyboardInterrupt:
            raise KeyboardInterruptError

        msg = "Completed job({})".format(seed)
        logging.debug(msg)


class Seed:
    def __init__(self):
        pass

    def seed(self):
        """
        Returns a dict containing seed nodes:
        {
            1: "IP_ADDRESS_1",
            2: "IP_ADDRESS_2",
            ..
            N: "IP_ADDRESS_N",
        }
        """
        nodes = []
        nodes.extend(self.dns_seed_nodes())
        nodes.extend(self.hub_nodes())
        nodes.extend(self.static_seed_nodes())
        nodes = list(set(nodes))
        random.shuffle(nodes)
        return dict(enumerate(nodes, start=1))

    def dns_seed_nodes(self):
        """
        DNS seeds from
        https://github.com/bitcoin/bitcoin/blob/master/src/net.cpp
        Each of these DNS seeds should resolve to a list of seed nodes.
        """
        nodes = []
        dns_seeds = [
            "seed.bitcoin.sipa.be",
            "dnsseed.bluematt.me",
            "dnsseed.bitcoin.dashjr.org",
            "bitseed.xf2.org",
        ]

        for dns_seed in dns_seeds:
            output = dig(dns_seed).strip().split()
            nodes.extend(output)

        return nodes

    def hub_nodes(self):
        """
        Extends seed nodes with nodes from Blockchain.info hub nodes.
        """
        nodes = []
        url = "http://blockchain.info/hub-nodes"

        page = urlopen(url)
        nodes.extend(re.findall(r'/ip-address/(?P<ip_address>[\d.]+)', page))

        return nodes

    def static_seed_nodes(self):
        """
        Extends seed nodes with hardcoded nodes from static_seed_nodes.txt.
        """
        fname = "static_seed_nodes.txt"
        nodes = [node.strip() for node in open(fname, "r").readlines()]
        return nodes


class Database:
    def __init__(self, database=None):
        """
        Creates a SQLite database that will be used to store all known nodes.
        """
        self.database = database

        if not os.path.exists(self.database):
            logging.debug("Initializing {}".format(self.database))
            self.connection = sqlite3.connect(self.database,
                                              SETTINGS['database_timeout'])
            self.cursor = self.connection.cursor()

            stmts = [
                # nodes table
                "CREATE TABLE nodes (node TEXT UNIQUE)",
                "CREATE INDEX nodes_node_idx ON nodes (node)",

                # nodes_version table
                ("CREATE TABLE nodes_version (node TEXT UNIQUE, "
                    "protocol_version INTEGER, user_agent TEXT)"),
                "CREATE INDEX nodes_version_node_idx ON nodes_version (node)",

                # nodes_getaddr table
                "CREATE TABLE nodes_getaddr (node TEXT UNIQUE, data TEXT)",
                "CREATE INDEX nodes_getaddr_node_idx ON nodes_getaddr (node)",

                # jobs table
                ("CREATE TABLE jobs (job_id INTEGER UNIQUE, started TEXT, "
                    "completed TEXT, data TEXT)"),
            ]
            for stmt in stmts:
                self.cursor.execute(stmt)
        else:
            self.connection = sqlite3.connect(self.database,
                                              SETTINGS['database_timeout'])
            self.cursor = self.connection.cursor()
            self.cursor.execute("PRAGMA synchronous = OFF")
            self.cursor.execute("PRAGMA journal_mode = MEMORY")

    def close(self):
        """
        Closes the database connection.
        """
        self.cursor.close()
        self.connection.close()

    def commit(self):
        """
        Commits the current transaction.
        """
        start = time.time()
        self.connection.commit()
        end = time.time()
        elapsed = int(end - start)
        if elapsed >= 0.8 * SETTINGS['database_timeout']:
            logging.warning("commit() took {} seconds".format(elapsed))

    def add_node(self, node):
        """
        Adds a new node into nodes table.
        """
        try:
            self.cursor.execute("INSERT INTO nodes VALUES (?)", (node,))
            self.commit()
        except sqlite3.IntegrityError:
            pass

    def add_node_version(self, node, version):
        """
        Adds a new node with version information into nodes_version table.
        """
        protocol_version = version.get('version', '')
        user_agent = version.get('user_agent', '')
        try:
            self.cursor.execute("INSERT INTO nodes_version VALUES (?, ?, ?)",
                                (node, protocol_version, user_agent,))
            self.commit()
        except sqlite3.IntegrityError:
            pass

    def add_node_getaddr(self, node, data):
        """
        Adds a new node with getaddr information into nodes_getaddr table.
        """
        try:
            self.cursor.execute("INSERT INTO nodes_getaddr VALUES (?, ?)",
                                (node, data,))
            self.commit()
        except sqlite3.IntegrityError:
            pass

    def get_node_getaddr(self, node):
        """
        Returns stored getaddr information for the given node.
        """
        self.cursor.execute("SELECT data FROM nodes_getaddr WHERE node = ?",
                            (node,))
        return self.cursor.fetchone()[0]

    def has_node(self, node, table="nodes"):
        """
        Returns True if node exists in table; False if otherwise.
        """
        self.cursor.execute("SELECT node FROM {} WHERE node = ?".format(
                            table), (node,))
        if self.cursor.fetchone() is not None:
            return True
        else:
            return False

    def count_nodes(self, table="nodes"):
        """
        Returns number of nodes in table.
        """
        self.cursor.execute("SELECT COUNT(node) FROM {}".format(table))
        return self.cursor.fetchone()[0]

    def set_job_started(self, job_id, data):
        """
        Sets the started time for the specified job in jobs table.
        """
        started = str(datetime.datetime.now())
        self.cursor.execute("INSERT INTO jobs VALUES (?, ?, ?, ?)",
                            (job_id, started, "", data,))
        self.commit()

    def set_job_completed(self, job_id):
        """
        Sets the completed time for the specified job in jobs table.
        """
        completed = str(datetime.datetime.now())
        self.cursor.execute("UPDATE jobs SET completed=? WHERE job_id=?",
                            (completed, job_id,))
        self.commit()


class Network:
    def __init__(self, seed=None):
        (self.seed_id, self.seed_ip) = seed
        self.database = Database(database=SETTINGS['database'])

    def traverse_network(self):
        """
        Calls get_nodes() to recursively get and store all adjacent nodes
        starting from a seed node that has at least one adjacent node.
        """
        self.database.set_job_started(self.seed_id, self.seed_ip)

        if len(self.getaddr(self.seed_ip)) > 0:
            self.get_nodes(self.seed_ip)
        else:
            logging.debug("({}) no adjacent nodes".format(self.seed_ip))

        self.database.set_job_completed(self.seed_id)
        self.database.close()

    def get_nodes(self, node, port=DEFAULT_PORT, depth=0):
        """
        Adds a new node into the database recursively until we exhaust all
        adjacent nodes.
        """
        if SETTINGS['max_depth'] >= 0 and depth >= SETTINGS['max_depth']:
            return

        logging.debug("depth = {}".format(depth))

        if self.database.has_node(node):
            return

        self.database.add_node(node)

        for child_node in self.getaddr(node, port):
            child_node_ip = child_node['ip']
            child_node_port = child_node.get('port', DEFAULT_PORT)

            if len(self.getaddr(child_node_ip, child_node_port)) > 0:
                self.get_nodes(child_node_ip, port=child_node_port,
                               depth=depth + 1)

            elif not self.database.has_node(child_node_ip):
                self.database.add_node(child_node_ip)

    def getaddr(self, node, port=DEFAULT_PORT):
        """
        Returns list of adjacent nodes using getaddr message described in
        https://en.bitcoin.it/wiki/Protocol_specification#getaddr.

        In a test run, we construct a dummy network to quickly test our
        network traversal function, i.e. get_nodes().
        """
        if SETTINGS['test']:
            return dummy_getaddr(node)

        if self.database.has_node(node, table="nodes_getaddr"):
            return json.loads(self.database.get_node_getaddr(node))

        return self._getaddr(node, port)

    def _getaddr(self, node, port):
        """
        Establishes connection with a node to:
        1) Send version message
        2) Receive version and verack message
        3) Send getaddr message
        4) Receive addr message containing list of adjacent nodes
        """
        to_addr = (node, port)
        conn = Connection(to_addr, timeout=SETTINGS['socket_timeout'])

        handshake_msgs = []
        addr_msg = {}
        try:
            conn.open()
            handshake_msgs = conn.handshake()
            addr_msg = conn.getaddr()
        except ProtocolError, err:
            logging.debug("{}: {} dropped".format(err, to_addr))
        except socket.error, err:
            logging.debug("{}: {} dropped".format(err, to_addr))
        finally:
            conn.close()

        # Record version information for the remote node
        if len(handshake_msgs) > 0:
            if not self.database.has_node(node, table="nodes_version"):
                self.database.add_node_version(node, handshake_msgs[0])

        nodes = []
        if 'addr_list' in addr_msg:
            nodes = self.get_nodes_from_addr_list(addr_msg['addr_list'])

        # Cache the result in database for reuse in subsequent getaddr()
        # calls for the same node.
        self.database.add_node_getaddr(node, json.dumps(nodes))

        return nodes

    def get_nodes_from_addr_list(self, addr_list):
        """
        Returns list of dicts each containing timestamp, IP and port
        information for an active node.
        """
        nodes = []
        now = int(time.time())

        for addr in addr_list:
            timestamp = addr['timestamp']
            if (now - timestamp) <= SETTINGS['max_age']:
                node = {
                    "ip": addr['ipv4'],
                    "port": addr['port'],
                }
                nodes.append(node)

        logging.debug("addr_list {}/{}".format(len(nodes), len(addr_list)))

        return nodes


def main(argv):
    if len(argv) < 2 or not os.path.exists(argv[1]):
        print("Usage: bitnodes.py [config]")
        return 1

    # Initialize settings
    conf = ConfigParser()
    conf.read(argv[1])
    SETTINGS['logfile'] = conf.get('bitnodes', 'logfile')
    SETTINGS['database'] = conf.get('bitnodes', 'database')
    SETTINGS['dig'] = conf.get('bitnodes', 'dig')
    SETTINGS['processes'] = conf.getint('bitnodes', 'processes')
    SETTINGS['debug'] = conf.getboolean('bitnodes', 'debug')
    SETTINGS['test'] = conf.getboolean('bitnodes', 'test')
    SETTINGS['socket_timeout'] = conf.getint('bitnodes', 'socket_timeout')
    SETTINGS['database_timeout'] = conf.getint('bitnodes', 'database_timeout')
    SETTINGS['status_interval'] = conf.getint('bitnodes', 'status_interval')
    SETTINGS['max_depth'] = conf.getint('bitnodes', 'max_depth')
    SETTINGS['max_age'] = conf.getint('bitnodes', 'max_age')

    # Initialize logger
    loglevel = logging.INFO
    if SETTINGS['debug']:
        loglevel = logging.DEBUG
    logformat = "%(levelname)s %(asctime)s %(process)d %(message)s"
    logging.basicConfig(level=loglevel,
                        format=logformat,
                        filename=SETTINGS['logfile'],
                        filemode='w')
    print("Writing output to {}, press CTRL+C to terminate..".format(
        SETTINGS['logfile']))

    # Get seed nodes
    seeds = {}
    if SETTINGS['test']:
        seeds = DUMMY_SEEDS
    else:
        seeds = Seed().seed()
    logging.info("Starting bitnodes with {} seed nodes".format(len(seeds)))

    # Initialize storage, uses a SQLite database
    database = Database(database=SETTINGS['database'])
    database.close()

    # Initialize a pool of workers to traverse network
    pool = Pool(SETTINGS['processes'])
    try:
        # Reserve a slot for periodical status reporting
        seeds[0] = "stat"
        pool.map(job, seeds.items())
        pool.close()
        logging.info("Bitnodes has completed successfully!")
    except KeyboardInterrupt:
        logging.info("CTRL+C pressed, terminating pool..")
        pool.terminate()
    except Exception, err:
        logging.error("{}, terminating pool..".format(err))
        pool.terminate()
    finally:
        pool.join()

    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
