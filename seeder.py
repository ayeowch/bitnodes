#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# seeder.py - Exports reachable nodes into DNS zone files for DNS seeder.
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
Exports reachable nodes into DNS zone files for DNS seeder.
"""

import glob
import json
import logging
import operator
import os
import random
import requests
import sys
import time
from collections import defaultdict
from ConfigParser import ConfigParser
from ipaddress import ip_address, ip_network

from utils import new_redis_conn

REDIS_CONN = None
CONF = {}


class Seeder(object):
    """
    Implements seeding mechanic by exporting reachable nodes as A and AAAA
    records into DNS zone files. A separate DNS server software is expected to
    consume and serve the zone files to the public.
    """
    def __init__(self):
        self.dump = None
        self.nodes = []
        self.addresses = defaultdict(list)
        self.now = 0
        self.blocklist = set()
        self.blocklist_timestamp = 0

    def export_nodes(self, dump):
        """
        Exports nodes to generate A and AAAA records from the latest snapshot.
        """
        self.now = int(time.time())
        if self.now - self.blocklist_timestamp > 3600:
            self.update_blocklist()
        if dump != self.dump:
            try:
                self.nodes = json.loads(open(dump, "r").read(),
                                        encoding="latin-1")
            except ValueError:
                logging.warning("Write pending")
                return
            if len(self.nodes) == 0:
                logging.warning("len(self.nodes): %d", len(self.nodes))
                return
            self.addresses = defaultdict(list)
            for address, services in self.filter_nodes():
                self.addresses[services].append(address)
            self.dump = dump
        self.save_zone_files()

    def save_zone_files(self):
        """
        Saves A and AAAA records in DNS zone files.
        """
        default_zone = os.path.basename(CONF['zone_file'])
        for i in range(0xf + 1):
            if i == 0:
                zone = default_zone
                zone_file = CONF['zone_file']
                wildcard = "".join([
                    "\n",
                    "*.{0}.\tIN\tCNAME\t{0}.".format(default_zone),
                ])
                addresses = []
                for services, addrs in self.addresses.iteritems():
                    if services & 1 == 1:  # NODE_NETWORK
                        addresses.extend(addrs)
            else:
                zone = 'x%x.%s' % (i, default_zone)
                zone_file = CONF['zone_file'].replace(default_zone, zone)
                wildcard = ""
                addresses = self.addresses[i]
            logging.debug("Zone file: %s", zone_file)
            serial = str(self.now)
            logging.debug("Serial: %s", serial)
            template = open(CONF['template'], "r") \
                .read() \
                .replace("1501826735", serial) \
                .replace("seed.bitnodes.io.", zone.replace("zone", ""))
            content = "".join([
                template,
                wildcard,
                "\n",
                self.get_records(addresses),
            ]).strip() + "\n"
            open(zone_file, "w").write(content)

    def get_records(self, addresses):
        """
        Returns addresses formatted in A, AAAA, TXT records for a zone file.
        """
        a_records = []
        aaaa_records = []
        txt_records = []
        for address in addresses:
            if address.endswith(".onion"):
                txt_records.append("@\tIN\tTXT\t{}".format(address))
            elif ":" in address:
                aaaa_records.append("@\tIN\tAAAA\t{}".format(address))
            else:
                a_records.append("@\tIN\tA\t{}".format(address))
        logging.debug("A records: %d", len(a_records))
        logging.debug("AAAA records: %d", len(aaaa_records))
        logging.debug("TXT records: %d", len(txt_records))
        random.shuffle(a_records)
        random.shuffle(aaaa_records)
        random.shuffle(txt_records)
        records = "".join([
            "\n".join(a_records[:CONF['a_records']]),
            "\n",
            "\n".join(aaaa_records[:CONF['aaaa_records']]),
            "\n",
            "\n".join(txt_records[:CONF['txt_records']]),
        ])
        return records

    def filter_nodes(self):
        """
        Returns nodes that satisfy the minimum requirements listed below:
        1) Height must be at most 2 blocks away from the consensus height
        2) Uptime must be equal or greater than the configured min. age
        3) Max. one node per ASN
        4) Uses default port
        5) Not listed in blocklist
        """
        consensus_height = self.get_consensus_height()
        min_age = self.get_min_age()
        asns = set()
        for node in self.nodes:
            address = node[0]
            port = node[1]
            age = self.now - node[4]
            services = node[5]
            height = node[6]
            asn = node[13]
            if (port != CONF['port'] or
                    asn is None or
                    age < min_age or
                    self.is_blocked(address)):
                continue
            if consensus_height and abs(consensus_height - height) > 2:
                continue
            if asn in asns and not address.endswith(".onion"):
                continue
            yield address, services
            asns.add(asn)

    def get_consensus_height(self):
        """
        Returns the most common height from Redis.
        """
        height = REDIS_CONN.get('height')
        if height:
            height = int(height)
        logging.info("Consensus. height: %s", height)
        return height

    def get_min_age(self):
        """
        Returns the minimum required uptime. If the oldest node cannot satisfy
        the configured value, use a fallback value of max. 1 percent away from
        the uptime of the oldest node.
        """
        min_age = CONF['min_age']
        oldest = self.now - min(self.nodes, key=operator.itemgetter(4))[4]
        logging.info("Longest uptime: %d", oldest)
        if oldest < min_age:
            min_age = oldest - (0.01 * oldest)  # Max. 1% newer than oldest
        logging.info("Min. age: %d", min_age)
        return min_age

    def is_blocked(self, address):
        """
        Returns True if address is found in blocklist, False if otherwise.
        """
        if address.endswith(".onion") or ":" in address:
            return False
        for network in self.blocklist:
            if ip_address(address) in network:
                logging.debug("Blocked: %s", address)
                return True
        return False

    def update_blocklist(self):
        """
        Fetches the latest DROP (don't route or peer) list from Spamhaus:
        http://www.spamhaus.org/faq/section/DROP%20FAQ
        """
        urls = [
            "http://www.spamhaus.org/drop/drop.txt",
            "http://www.spamhaus.org/drop/edrop.txt",
        ]
        self.blocklist.clear()
        for url in urls:
            try:
                response = requests.get(url, timeout=15)
            except requests.exceptions.RequestException as err:
                logging.warning(err)
                continue
            if response.status_code == 200:
                for line in response.content.strip().split("\n"):
                    if line.startswith(";"):
                        continue
                    network = line.split(";")[0].strip()
                    try:
                        self.blocklist.add(ip_network(unicode(network)))
                    except ValueError:
                        continue
            else:
                logging.warning("HTTP%d: %s (%s)",
                                response.status_code, url, response.content)
        logging.debug("Blocklist entries: %d", len(self.blocklist))
        self.blocklist_timestamp = self.now


def cron():
    """
    Periodically fetches latest snapshot to sample nodes for DNS zone files.
    """
    seeder = Seeder()
    while True:
        time.sleep(5)
        try:
            dump = max(glob.iglob("{}/*.json".format(CONF['export_dir'])))
        except ValueError as err:
            logging.warning(err)
            continue
        logging.info("Dump: %s", dump)
        seeder.export_nodes(dump)


def init_conf(argv):
    """
    Populates CONF with key-value pairs from configuration file.
    """
    conf = ConfigParser()
    conf.read(argv[1])
    CONF['logfile'] = conf.get('seeder', 'logfile')
    CONF['port'] = conf.getint('seeder', 'port')
    CONF['db'] = conf.getint('seeder', 'db')
    CONF['debug'] = conf.getboolean('seeder', 'debug')
    CONF['export_dir'] = conf.get('seeder', 'export_dir')
    CONF['min_age'] = conf.getint('seeder', 'min_age')
    CONF['zone_file'] = conf.get('seeder', 'zone_file')
    CONF['template'] = conf.get('seeder', 'template')
    CONF['a_records'] = conf.getint('seeder', 'a_records')
    CONF['aaaa_records'] = conf.getint('seeder', 'aaaa_records')
    CONF['txt_records'] = conf.getint('seeder', 'txt_records')
    zone_dir = os.path.dirname(CONF['zone_file'])
    if not os.path.exists(zone_dir):
        os.makedirs(zone_dir)


def main(argv):
    if len(argv) < 2 or not os.path.exists(argv[1]):
        print("Usage: seeder.py [config]")
        return 1

    # Initialize global conf
    init_conf(argv)

    # Initialize logger
    loglevel = logging.INFO
    if CONF['debug']:
        loglevel = logging.DEBUG

    logformat = ("%(asctime)s,%(msecs)05.1f %(levelname)s (%(funcName)s) "
                 "%(message)s")
    logging.basicConfig(level=loglevel,
                        format=logformat,
                        filename=CONF['logfile'],
                        filemode='w')
    print("Log: {}, press CTRL+C to terminate..".format(CONF['logfile']))

    global REDIS_CONN
    REDIS_CONN = new_redis_conn(db=CONF['db'])

    cron()

    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
