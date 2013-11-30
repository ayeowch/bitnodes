#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# bitnodes.py - Exhaustively get all connected Bitcoin nodes.
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
Exhaustively get all connected Bitcoin nodes.
"""

import datetime
import httplib
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
from multiprocessing import Pool, Value
from subprocess import Popen, PIPE

from protocol import ProtocolError, Connection, DEFAULT_PORT, MAX_ADDR_COUNT
from tests import DUMMY_SEEDS, dummy_getaddr

SETTINGS = {}

# Set when number of found nodes per interval fell below set limit
_MIN_DELTA = Value('i', 0)


def execute_cmd(cmd):
    """
    Executes given command using subprocess.Popen().
    """
    logging.debug("[{}]".format(cmd))

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
    response = ""
    request = urllib2.Request(url=url)
    request.add_header('User-Agent', 'Mozilla/5.0')

    logging.debug("[{}]".format(url))

    try:
        response = urllib2.urlopen(request).read()
    except urllib2.HTTPError, err:
        logging.warning("HTTPError: {} ({})".format(url, err.code))
    except urllib2.URLError, err:
        logging.warning("URLError: {} ({})".format(url, err.reason))
    except httplib.IncompleteRead, err:
        logging.warning("{}: {}".format(err, url))

    return response


def status():
    """
    Logs the number of nodes found so far on a periodical basis.
    """
    current = 0
    last = 0
    deltas = []
    database = Database(database=SETTINGS['database'])

    while True:
        time.sleep(SETTINGS['status_interval'])

        if SETTINGS['test']:
            current = database.count_nodes(table="nodes")
        else:
            current = database.count_nodes(table="nodes_getaddr")

        # Stop reporting if no more changes
        if current == last:
            logging.debug("status() stopped, {} == {}".format(current, last))
            break

        delta = current - last

        if SETTINGS['min_delta'] > 0:
            deltas.append(delta)
            if delta < (SETTINGS['min_delta'] * sum(deltas) / len(deltas)):
                logging.debug("status() min. delta hit = {}".format(delta))
                _MIN_DELTA.value = delta

        logging.info("Found {} nodes (+{})".format(current, delta))
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
    traverse the network.
    seed with tuple (0, 'stat') is reserved for periodical status reporting.
    """
    if seed[1] == "stat":
        try:
            status()
        except KeyboardInterrupt:
            raise KeyboardInterruptError

    else:
        logging.debug("Started job({})".format(seed))

        try:
            network = Network(seed=seed)
            network.traverse_network()
        except KeyboardInterrupt:
            raise KeyboardInterruptError

        logging.debug("Completed job({})".format(seed))


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
        All seed nodes are expected to run on the DEFAULT_PORT.
        """
        nodes = []

        nodes.extend(self.dns_seed_nodes())
        nodes.extend(self.static_list_nodes())
        nodes.extend(self.static_page_nodes())
        nodes.extend(self.last_run())

        nodes = list(set(nodes))
        random.shuffle(nodes)
        return dict(enumerate(nodes, start=1))

    def dns_seed_nodes(self):
        """
        DNS seeds from
        https://github.com/bitcoin/bitcoin/blob/master/src/chainparams.cpp
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

    def static_list_nodes(self):
        """
        Extends seed nodes with nodes from text files.
        pnSeed.txt contains nodes from pnSeed[] in
        https://github.com/bitcoin/bitcoin/blob/master/src/chainparams.cpp
        """
        nodes = []
        text_files = [
            "pnSeed.txt",
        ]

        for text_file in text_files:
            nodes.extend(
                [node.strip() for node in open(text_file, "r").readlines()])

        return nodes

    def static_page_nodes(self):
        """
        Extends seed nodes with nodes from blockchain.info static pages.
        """
        nodes = []
        static_pages = [
            "http://blockchain.info/connected-nodes",
            "http://blockchain.info/hub-nodes",
        ]

        for static_page in static_pages:
            page = urlopen(static_page)
            regex = r'/ip-address/(?P<ip_address>[\d.]+)'
            nodes.extend(re.findall(regex, page))

        return nodes

    def last_run(self):
        """
        Extends seed nodes with nodes with peers from previous run.
        """
        nodes = urlopen("http://getaddr.bitnodes.io/seeds/")
        return json.loads(nodes)


class Database:
    def __init__(self, database):
        """
        Creates a SQLite database that will be used to store all known nodes.
        """
        self.database = database

        if not os.path.exists(self.database):
            logging.debug("Initializing {}".format(self.database))
            self.connection = sqlite3.connect(self.database,
                                              SETTINGS['database_timeout'])
            self.cursor = self.connection.cursor()
            self.cursor.execute("PRAGMA journal_mode = WAL")

            stmts = [
                # nodes table
                "CREATE TABLE nodes (node TEXT UNIQUE, port INTEGER)",
                "CREATE INDEX nodes_node_idx ON nodes (node)",

                # nodes_version table
                ("CREATE TABLE nodes_version (node TEXT UNIQUE, "
                    "protocol_version INTEGER, user_agent TEXT)"),
                "CREATE INDEX nodes_version_node_idx ON nodes_version (node)",

                # nodes_getaddr table
                ("CREATE TABLE nodes_getaddr (node TEXT UNIQUE, data TEXT, "
                    "error TEXT, degree INTEGER)"),
                "CREATE INDEX nodes_getaddr_node_idx ON nodes_getaddr (node)",

                # jobs table
                ("CREATE TABLE jobs (job_id INTEGER UNIQUE, started TEXT, "
                    "completed TEXT, seed_ip TEXT, added INTEGER, "
                    "depth INTEGER)"),
            ]
            for stmt in stmts:
                self.cursor.execute(stmt)
        else:
            self.connection = sqlite3.connect(self.database,
                                              SETTINGS['database_timeout'])
            self.cursor = self.connection.cursor()
            self.cursor.execute("PRAGMA synchronous = OFF")
            self.cursor.execute("PRAGMA temp_store = MEMORY")
            self.cursor.execute("PRAGMA read_uncommitted = true")

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

    def fetchone(self):
        """
        Fetches the next row of a query result.
        """
        start = time.time()
        result = self.cursor.fetchone()
        end = time.time()
        elapsed = int(end - start)
        if elapsed >= 0.8 * SETTINGS['database_timeout']:
            logging.warning("fetchone() took {} seconds".format(elapsed))
        return result

    def add_node(self, node, port):
        """
        Adds a new node into nodes table.
        """
        try:
            self.cursor.execute("INSERT INTO nodes VALUES (?, ?)",
                                (node, port,))
            self.commit()
        except sqlite3.IntegrityError:
            pass

    def add_node_version(self, node, version):
        """
        Adds a new node with version information into nodes_version table.
        """
        protocol_version = version.get('version', "")
        user_agent = version.get('user_agent', "")
        try:
            self.cursor.execute("INSERT INTO nodes_version VALUES (?, ?, ?)",
                                (node, protocol_version, user_agent,))
            self.commit()
        except sqlite3.IntegrityError:
            pass

    def add_node_getaddr(self, node, nodes, error, degree):
        """
        Adds a new node with getaddr information into nodes_getaddr table.
        Existing row will be updated accordingly, e.g. new nodes are appended
        into existing data column.
        """
        self.cursor.execute("SELECT data FROM nodes_getaddr WHERE node = ?",
                            (node,))
        row = self.fetchone()
        if row is not None:
            existing_nodes = json.loads(row[0])
            if nodes is not None and existing_nodes is not None:
                nodes += existing_nodes
                nodes = {_['ip']: _ for _ in nodes}.values()
                degree = len(nodes)
            self.cursor.execute("UPDATE nodes_getaddr SET data=?, error=?, "
                                "degree=? WHERE node=?", (json.dumps(nodes),
                                error, degree, node,))
            self.commit()
        else:
            try:
                self.cursor.execute("INSERT INTO nodes_getaddr VALUES "
                                    "(?, ?, ?, ?)", (node, json.dumps(nodes),
                                    error, degree,))
                self.commit()
            except sqlite3.IntegrityError:
                pass

    def get_node_getaddr(self, node):
        """
        Returns stored getaddr information for the given node.
        """
        self.cursor.execute("SELECT data FROM nodes_getaddr WHERE node = ?",
                            (node,))
        return self.fetchone()[0]

    def has_node(self, node, table="nodes"):
        """
        Returns True if node exists in table; False if otherwise.
        """
        self.cursor.execute("SELECT node FROM {} WHERE node = ?".format(
                            table), (node,))
        if self.fetchone() is not None:
            return True
        else:
            return False

    def count_nodes(self, table="nodes"):
        """
        Returns number of nodes in table.
        """
        self.cursor.execute("SELECT COUNT(node) FROM {}".format(table))
        return self.fetchone()[0]

    def set_job_started(self, job_id, seed_ip):
        """
        Sets the started time for the specified job in jobs table.
        """
        started = str(datetime.datetime.now())
        self.cursor.execute("INSERT INTO jobs VALUES (?, ?, ?, ?, ?, ?)",
                            (job_id, started, "", seed_ip, 0, 0,))
        self.commit()

    def set_job_completed(self, job_id, added, depth):
        """
        Sets the completed time for the specified job in jobs table.
        """
        completed = str(datetime.datetime.now())
        self.cursor.execute(
            "UPDATE jobs SET completed=?, added=?, depth=? WHERE job_id=?",
            (completed, added, depth, job_id,))
        self.commit()


class Network:
    def __init__(self, seed):
        (self.seed_id, self.seed_ip) = seed
        self.database = Database(database=SETTINGS['database'])

    def traverse_network(self):
        """
        Calls get_nodes() to exhaustively get all adjacent nodes if seed node
        is reachable.
        """
        self.database.set_job_started(self.seed_id, self.seed_ip)

        added = 0
        depth = 0
        if self.getaddr(self.seed_ip) is not None:
            (added, depth) = self.get_nodes(self.seed_ip)
        else:
            # Seed node did not respond to our version message
            logging.debug("{} noack".format(self.seed_ip))

        self.database.set_job_completed(self.seed_id, added, depth)
        self.database.close()

    def get_nodes(self, root_node):
        """
        Uses non-recursive DFS to get and store all reachable nodes starting
        from the specified root node. Returns a tuple containing number of
        nodes added and depth reached as of deepest parent node.
        """
        added = 0
        depth = 0

        current_nodes = set([(root_node, DEFAULT_PORT)])

        while current_nodes:
            next_nodes = set()
            logging.debug("[{}] depth = {}".format(root_node, depth))

            for node in current_nodes:
                (node_ip, node_port) = node
                if not self.database.has_node(node_ip):
                    logging.debug("[{}] adding {}".format(root_node, node))
                    self.database.add_node(node_ip, node_port)
                    added += 1
                else:
                    continue

                childs = self.getaddr(node_ip, node_port)
                if childs is None:
                    continue

                for child in childs:
                    child_ip = child['ip']
                    child_port = child.get('port', DEFAULT_PORT)
                    if self.database.has_node(child_ip):
                        continue

                    if _MIN_DELTA.value != 0:
                        logging.debug("[{}] min. delta set".format(root_node))
                        return (added, depth)

                    child_getaddr = self.getaddr(child_ip, child_port)
                    if SETTINGS['greedy'] or child_getaddr is not None:
                        next_nodes.add((child_ip, child_port))

            current_nodes = next_nodes
            if current_nodes:
                if (SETTINGS['max_depth'] >= 0 and
                        depth >= SETTINGS['max_depth']):
                    break
                depth += 1

        return (added, depth)

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

        nodes = self._getaddr(node, port)

        if (nodes is not None and len(nodes) == MAX_ADDR_COUNT and
                SETTINGS['max_getaddr'] > 1):
            for _ in xrange(SETTINGS['max_getaddr'] - 1):
                _nodes = self._getaddr(node, port)
                if _nodes is not None and len(_nodes) > 0:
                    nodes.extend(_nodes)
                else:
                    break

        return nodes

    def _getaddr(self, node, port):
        """
        Establishes connection with a node to:
        1) Send version message
        2) Receive version and verack message
        3) Send getaddr message
        4) Receive addr message containing list of adjacent nodes
        """
        to_addr = (node, port)
        conn = Connection(to_addr, socket_timeout=SETTINGS['socket_timeout'],
                          user_agent=SETTINGS['user_agent'],
                          start_height=SETTINGS['start_height'])

        error = ""
        handshake_msgs = []
        addr_msg = {}
        try:
            conn.open()
            handshake_msgs = conn.handshake()
            addr_msg = conn.getaddr()
        except (ProtocolError, socket.error) as err:
            error = str(err)
            logging.debug("{}: {} dropped".format(err, to_addr))
        finally:
            conn.close()

        nodes = None
        degree = 0

        # Record version information for the remote node
        if len(handshake_msgs) > 0:
            if not self.database.has_node(node, table="nodes_version"):
                self.database.add_node_version(node, handshake_msgs[0])

            nodes = []
            if 'addr_list' in addr_msg:
                nodes = self.get_nodes_from_addr_list(addr_msg['addr_list'])
                degree = len(nodes)

        # Cache the result in database for reuse in subsequent getaddr()
        # calls for the same node.
        self.database.add_node_getaddr(node, nodes, error, degree)

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
                    'ip': addr['ipv4'],
                    'port': addr['port'],
                }
                nodes.append(node)

        logging.debug("addr_list {}/{}".format(len(nodes), len(addr_list)))

        return nodes


def init_settings(argv):
    """
    Populates SETTINGS with key-value pairs from configuration file.
    """
    conf = ConfigParser()
    conf.read(argv[1])
    SETTINGS['logfile'] = conf.get('bitnodes', 'logfile')
    SETTINGS['database'] = conf.get('bitnodes', 'database')
    SETTINGS['dig'] = conf.get('bitnodes', 'dig')
    SETTINGS['workers'] = conf.getint('bitnodes', 'workers')
    SETTINGS['debug'] = conf.getboolean('bitnodes', 'debug')
    SETTINGS['test'] = conf.getboolean('bitnodes', 'test')
    SETTINGS['user_agent'] = conf.get('bitnodes', 'user_agent')
    SETTINGS['start_height'] = conf.getint('bitnodes', 'start_height')
    SETTINGS['socket_timeout'] = conf.getint('bitnodes', 'socket_timeout')
    SETTINGS['database_timeout'] = conf.getint('bitnodes', 'database_timeout')
    SETTINGS['status_interval'] = conf.getint('bitnodes', 'status_interval')
    SETTINGS['max_depth'] = conf.getint('bitnodes', 'max_depth')
    SETTINGS['max_age'] = conf.getint('bitnodes', 'max_age')
    SETTINGS['min_delta'] = conf.getfloat('bitnodes', 'min_delta')
    SETTINGS['greedy'] = conf.getboolean('bitnodes', 'greedy')
    SETTINGS['max_getaddr'] = conf.getint('bitnodes', 'max_getaddr')


def main(argv):
    if len(argv) < 2 or not os.path.exists(argv[1]):
        print("Usage: bitnodes.py [config]")
        return 1

    # Initialize settings
    init_settings(argv)

    # Initialize logger
    loglevel = logging.INFO
    if SETTINGS['debug']:
        loglevel = logging.DEBUG
    logformat = ("%(levelname)7s %(asctime)s %(process)5d %(message)s")
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

    # Get current start height
    if SETTINGS['start_height'] == 0:
        page = urlopen("https://dazzlepod.com/bitcoin/getblockcount/")
        SETTINGS['start_height'] = int(page)
        logging.info("Start height set to {}".format(SETTINGS['start_height']))

    # Backup previous database
    if os.path.exists(SETTINGS['database']):
        os.rename(SETTINGS['database'], SETTINGS['database'] + ".old")

    # Initialize storage, uses a SQLite database
    database = Database(database=SETTINGS['database'])
    database.close()

    # Reserve a slot for periodical status reporting
    seeds[0] = "stat"

    # Initialize a pool of workers to traverse network
    pool = Pool(SETTINGS['workers'])
    try:
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
