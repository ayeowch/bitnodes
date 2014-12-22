#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# seeder.py - Exports reachable nodes into a DNS zone file for DNS seeder.
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
Exports reachable nodes into a DNS zone file for DNS seeder.
"""

import glob
import json
import logging
import operator
import os
import random
import redis
import requests
import sys
import time
from ConfigParser import ConfigParser
from ipaddress import ip_address, ip_network

from protocol import DEFAULT_PORT

# Redis connection setup
REDIS_SOCKET = os.environ.get('REDIS_SOCKET', "/tmp/redis.sock")
REDIS_PASSWORD = os.environ.get('REDIS_PASSWORD', None)
REDIS_CONN = redis.StrictRedis(unix_socket_path=REDIS_SOCKET,
                               password=REDIS_PASSWORD)

SETTINGS = {}


class Seeder(object):
    """
    Implements seeding mechanic by exporting reachable nodes as A and AAAA
    records into a DNS zone file. A separate DNS server software is expected to
    consume and serve the zone file to the public.
    """
    def __init__(self):
        self.dump = None
        self.nodes = []
        self.a_records = []
        self.aaaa_records = []
        self.now = 0
        self.blocklist = set()
        self.blocklist_timestamp = 0

    def export_nodes(self, dump):
        """
        Exports nodes as A and AAAA records from the latest snapshot.
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
            self.a_records = []
            self.aaaa_records = []
            for address in self.filter_nodes():
                if ":" in address:
                    self.aaaa_records.append("@\tIN\tAAAA\t{}".format(address))
                else:
                    self.a_records.append("@\tIN\tA\t{}".format(address))
            self.dump = dump
        self.save_zone_file()

    def save_zone_file(self):
        """
        Saves A and AAAA records in DNS zone file.
        """
        logging.info("A records: {}".format(len(self.a_records)))
        logging.info("AAAA records: {}".format(len(self.aaaa_records)))
        random.shuffle(self.a_records)
        random.shuffle(self.aaaa_records)
        serial = str(self.now)
        logging.debug("Serial: {}".format(serial))
        template = open(SETTINGS['template'], "r").read()
        template = template.replace("1413235952", serial)
        content = "".join([
            template,
            "\n".join(self.a_records[:SETTINGS['a_records']]),
            "\n",
            "\n".join(self.aaaa_records[:SETTINGS['aaaa_records']]),
            "\n",
        ])
        open(SETTINGS['zone_file'], "w").write(content)

    def filter_nodes(self):
        """
        Returns nodes that satisfy the minimum requirements listed below:
        1) Height must be equal or greater than the consensus height
        2) Uptime must be equal or greater than the configured min. age
        3) Max. one node per ASN
        4) Uses default port, i.e. port 8333
        5) Not listed in blocklist
        """
        min_height = self.get_min_height()
        min_age = self.get_min_age()
        asns = set()
        for node in self.nodes:
            address = node[0]
            port = node[1]
            age = self.now - node[4]
            height = node[5]
            asn = node[12]
            if (port != DEFAULT_PORT or asn in asns or age < min_age or
                    height < min_height or self.is_blocked(address)):
                continue
            yield address
            asns.add(asn)

    def get_min_height(self):
        """
        Returns the most common height from Redis. If the value has not been
        set in Redis, use the configured fallback value.
        """
        min_height = REDIS_CONN.get('height')
        if min_height is None:
            min_height = SETTINGS['min_height']
        else:
            min_height = int(min_height)
        logging.info("Min. height: {}".format(min_height))
        return min_height

    def get_min_age(self):
        """
        Returns the minimum required uptime. If the oldest node cannot satisfy
        the configured value, use a fallback value of max. 1 percent away from
        the uptime of the oldest node.
        """
        min_age = SETTINGS['min_age']
        oldest = self.now - min(self.nodes, key=operator.itemgetter(4))[4]
        logging.info("Longest uptime: {}".format(oldest))
        if oldest < min_age:
            min_age = oldest - (0.01 * oldest)  # Max. 1% newer than oldest
        logging.info("Min. age: {}".format(min_age))
        return min_age

    def is_blocked(self, address):
        """
        Returns True if address is found in blocklist, False if otherwise.
        """
        if ":" in address:
            return False
        for network in self.blocklist:
            if ip_address(address) in network:
                logging.debug("Blocked: {}".format(address))
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
            response = requests.get(url)
            if response.status_code == 200:
                for line in response.content.strip().split("\n"):
                    if line.startswith(";"):
                        continue
                    network = line.split(";")[0].strip()
                    self.blocklist.add(ip_network(unicode(network)))
            else:
                logging.warning("HTTP{}: {} ({})".format(
                    response.status_code, url, response.content))
        logging.debug("Blocklist entries: {}".format(len(self.blocklist)))
        self.blocklist_timestamp = self.now


def cron():
    """
    Periodically fetches latest snapshot to sample nodes for DNS zone file.
    """
    seeder = Seeder()
    while True:
        time.sleep(5)
        dump = max(glob.iglob("{}/*.json".format(SETTINGS['export_dir'])))
        logging.info("Dump: {}".format(dump))
        seeder.export_nodes(dump)


def init_settings(argv):
    """
    Populates SETTINGS with key-value pairs from configuration file.
    """
    conf = ConfigParser()
    conf.read(argv[1])
    SETTINGS['logfile'] = conf.get('seeder', 'logfile')
    SETTINGS['debug'] = conf.getboolean('seeder', 'debug')
    SETTINGS['export_dir'] = conf.get('seeder', 'export_dir')
    SETTINGS['min_height'] = conf.getint('seeder', 'min_height')
    SETTINGS['min_age'] = conf.getint('seeder', 'min_age')
    SETTINGS['zone_file'] = conf.get('seeder', 'zone_file')
    SETTINGS['template'] = conf.get('seeder', 'template')
    SETTINGS['a_records'] = conf.getint('seeder', 'a_records')
    SETTINGS['aaaa_records'] = conf.getint('seeder', 'aaaa_records')


def main(argv):
    if len(argv) < 2 or not os.path.exists(argv[1]):
        print("Usage: seeder.py [config]")
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

    cron()

    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
