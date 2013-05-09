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

import logging
import os
import re
import socket
import sqlite3
import sys
import urllib2
from ConfigParser import ConfigParser
from multiprocessing import Pool
from subprocess import Popen, PIPE

from protocol import ProtocolError, Connection
from tests import DUMMY_SEEDS, dummy_getaddr

DEFAULT_PORT = 8333
SETTINGS = {}


def memoize(function):
    """
    A decorator to cache result from slow running function for reuse on
    subsequent calls, e.g. Network.getaddr().
    """
    mem = {}

    def wrapper(*args):
        if args in mem:
            return mem[args]
        else:
            value = function(*args)
            mem[args] = value
            return value

    return wrapper


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
        raise RuntimeError("{} failed: {}".format(cmd, stderr))

    return stdout


def dig(ip_address):
    """
    Performs DNS lookup against the given IP address using dig.
    """
    cmd = "{} +short {}".format(SETTINGS['dig'], ip_address)
    stdout = execute_cmd(cmd)
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
    """
    msg = "Started job({})".format(seed)
    logging.info(msg)

    network = Network(seed=seed)
    try:
        network.traverse_network()
    except KeyboardInterrupt:
        raise KeyboardInterruptError

    msg = "Completed job({})".format(seed)
    logging.info(msg)


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
        nodes = list(set(nodes))
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


class Database:
    def __init__(self, database=None):
        """
        Creates a SQLite database that will be used to store all known nodes.
        """
        self.database = database

        if not os.path.exists(self.database):
            logging.debug("Initializing {}".format(self.database))
            self.connection = sqlite3.connect(self.database)
            self.cursor = self.connection.cursor()
            self.cursor.execute("CREATE TABLE nodes (node TEXT UNIQUE)")
            self.cursor.execute("CREATE INDEX nodes_node_idx ON nodes (node)")
            self.connection.commit()
        else:
            logging.debug("Using {}".format(self.database))
            self.connection = sqlite3.connect(self.database)
            self.cursor = self.connection.cursor()
            self.cursor.execute("PRAGMA synchronous = OFF")

    def has_node(self, node):
        """
        Returns True if node exists in the nodes table; False if otherwise.
        """
        self.cursor.execute("SELECT node FROM nodes WHERE node = ?", (node,))
        if len(self.cursor.fetchall()) > 0:
            return True
        else:
            return False

    def add_node(self, node):
        """
        Adds a new node into the nodes table.
        """
        self.cursor.execute("INSERT INTO nodes VALUES (?)", (node,))
        self.connection.commit()

    def count_nodes(self):
        """
        Returns number of nodes in the nodes table.
        """
        self.cursor.execute("SELECT COUNT(node) FROM nodes")
        return self.cursor.fetchone()[0]


class Network:
    def __init__(self, seed=None):
        (self.seed_id, self.seed_ip) = seed
        self.database = Database(database=SETTINGS['database'])

    def traverse_network(self):
        """
        Calls get_nodes() to recursively get and store all adjacent nodes
        starting from a seed node that has at least one adjacent node.
        """
        if len(self.getaddr(self.seed_ip)) > 0:
            self.get_nodes(self.seed_ip)
            logging.info("({}) {} nodes stored".format(
                self.seed_id, self.database.count_nodes()))
        else:
            logging.info("({}) no adjacent nodes".format(self.seed_id))
        self.database.cursor.close()

    def get_nodes(self, node, port=DEFAULT_PORT):
        """
        Adds a new node into the database recursively until we exhaust all
        adjacent nodes.
        """
        if self.database.has_node(node):
            return

        self.database.add_node(node)

        for child_node in self.getaddr(node, port):
            child_node_ip = child_node['ip']
            child_node_port = child_node.get('port', DEFAULT_PORT)

            if len(self.getaddr(child_node_ip, child_node_port)) > 0:
                self.get_nodes(child_node_ip, child_node_port)

            elif not self.database.has_node(child_node_ip):
                self.database.add_node(child_node_ip)

    @memoize
    def getaddr(self, node, port=DEFAULT_PORT):
        """
        Returns list of adjacent nodes using getaddr message described in
        https://en.bitcoin.it/wiki/Protocol_specification#getaddr.

        In a test run, we construct a dummy network to quickly test our
        network traversal function, i.e. get_nodes().
        """
        if SETTINGS['test']:
            return dummy_getaddr(node)
        else:
            to_addr = (node, port)
            from_addr = ("0.0.0.0", 0)
            addr_msg = {}
            nodes = []

            connection = Connection(to_addr, from_addr,
                                    timeout=SETTINGS['timeout'])
            try:
                connection.open()
                connection.handshake()
                addr_msg = connection.getaddr()
            except ProtocolError, err:
                logging.debug("{}: {} dropped".format(err, to_addr))
            except socket.error, err:
                logging.debug("{}: {} dropped".format(err, to_addr))
            finally:
                connection.close()

            if 'addr_list' in addr_msg:
                logging.debug("len(addr_list) = {}".format(
                    len(addr_msg['addr_list'])))
                for addr in addr_msg['addr_list']:
                    nodes.append({"ip": addr['ipv4'], "port": addr['port']})

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
    SETTINGS['timeout'] = conf.getint('bitnodes', 'timeout')

    # Initialize logger
    loglevel = logging.INFO
    if SETTINGS['debug']:
        loglevel = logging.DEBUG
    logformat = "%(levelname)s %(asctime)s %(process)d %(message)s"
    logging.basicConfig(level=loglevel,
                        format=logformat,
                        filename=SETTINGS['logfile'],
                        filemode='w')
    print("Writing output to {}..".format(SETTINGS['logfile']))

    # Get seed nodes
    seeds = {}
    if SETTINGS['test']:
        seeds = DUMMY_SEEDS
    else:
        seeds = Seed().seed()

    # Initialize storage, uses a SQLite database
    database = Database(database=SETTINGS['database'])
    database.cursor.close()

    # Initialize a pool of workers to traverse network
    pool = Pool(SETTINGS['processes'])
    try:
        pool.map(job, seeds.items())
        pool.close()
    except KeyboardInterrupt:
        print("CTRL+C pressed, terminating pool..")
        pool.terminate()
    except Exception, err:
        print("ERROR: {}, terminating pool..".format(err))
        pool.terminate()
    finally:
        pool.join()

    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
