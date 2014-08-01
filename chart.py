#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# chart.py - Stores chart data from Bitcoin network pinger.
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
Stores chart data from Bitcoin network pinger.
"""

import glob
import json
import logging
import os
import redis
import sys
import threading
from collections import Counter
from ConfigParser import ConfigParser

# Redis connection setup
REDIS_SOCKET = os.environ.get('REDIS_SOCKET', "/tmp/redis.sock")
REDIS_PASSWORD = os.environ.get('REDIS_PASSWORD', None)
REDIS_CONN = redis.StrictRedis(unix_socket_path=REDIS_SOCKET,
                               password=REDIS_PASSWORD)

SETTINGS = {}


def get_chart_data(tick, nodes, prev_nodes):
    """
    Generates chart data for current tick using enumerated data for all
    reachable nodes.
    """
    data = {
        't': tick,
        'nodes': len(nodes),
        'ipv4': 0,
        'ipv6': 0,
        'user_agents': {},
        'countries': {},
        'coordinates': {},
        'orgs': {},
        'join': 0,
        'leave': 0,
        'heights': {},
    }
    curr_nodes = set()
    latest_height = Counter([node[5] for node in nodes]).most_common(1)[0][0]

    for node in nodes:
        #  0: address
        #  1: port
        #  2: version
        #  3: user_agent
        #  4: timestamp
        #  5: height
        #  6: hostname
        #  7: city
        #  8: country
        #  9: latitude
        # 10: longitude
        # 11: timezone
        # 12: asn
        # 13: org
        address = node[0]
        port = node[1]
        user_agent = node[3]
        height = node[5]
        country = node[8]
        latitude = node[9]
        longitude = node[10]
        org = node[13]

        curr_nodes.add((address, port))

        if ":" in address:
            data['ipv6'] += 1
        else:
            data['ipv4'] += 1

        data['user_agents'][user_agent] = data['user_agents'].get(
            user_agent, 0) + 1

        data['countries'][country] = data['countries'].get(country, 0) + 1

        coordinate = "%s,%s" % (latitude, longitude)
        data['coordinates'][coordinate] = data['coordinates'].get(
            coordinate, 0) + 1

        data['orgs'][org] = data['orgs'].get(org, 0) + 1

        # [height_id]
        # 0: head or > head
        # 1: head - 1
        # 2: head - 2
        # 3: < head - 2
        height_id = min(max(0, latest_height - height), 3)
        data['heights'][height_id] = data['heights'].get(height_id, 0) + 1

    data['join'] = len(curr_nodes - prev_nodes)
    data['leave'] = len(prev_nodes - curr_nodes)

    return data, curr_nodes


def replay_ticks():
    """
    Removes chart data and replays the published timestamps from export.py to
    recreate chart data.
    """
    keys = REDIS_CONN.keys('t:*')
    redis_pipe = REDIS_CONN.pipeline()
    for key in keys:
        redis_pipe.delete(key)
    redis_pipe.execute()

    files = sorted(glob.iglob("{}/*.json".format(SETTINGS['export_dir'])))
    if len(files) > SETTINGS['replay']:
        files = files[len(files) - SETTINGS['replay']:]
    for dump in files:
        timestamp = os.path.basename(dump).rstrip(".json")
        REDIS_CONN.publish('export', timestamp)


def init_settings(argv):
    """
    Populates SETTINGS with key-value pairs from configuration file.
    """
    conf = ConfigParser()
    conf.read(argv[1])
    SETTINGS['logfile'] = conf.get('chart', 'logfile')
    SETTINGS['debug'] = conf.getboolean('chart', 'debug')
    SETTINGS['interval'] = conf.getint('chart', 'interval')
    SETTINGS['export_dir'] = conf.get('chart', 'export_dir')
    SETTINGS['replay'] = conf.getint('chart', 'replay')


def main(argv):
    if len(argv) < 2 or not os.path.exists(argv[1]):
        print("Usage: chart.py [config]")
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

    threading.Thread(target=replay_ticks).start()

    prev_nodes = set()

    pubsub = REDIS_CONN.pubsub()
    pubsub.subscribe('export')
    for msg in pubsub.listen():
        # 'export' message is published by export.py after exporting enumerated
        # data for all reachable nodes.
        if msg['channel'] == 'export' and msg['type'] == 'message':
            timestamp = int(msg['data'])  # From ping.py's 'snapshot' message

            # Normalize timestamp to fixed length tick
            floor = timestamp - (timestamp % SETTINGS['interval'])
            tick = floor + SETTINGS['interval']

            # Only the first snapshot before the next interval is used to
            # generate the chart data for each tick.
            if REDIS_CONN.zcount("t:m:timestamp", tick, tick) == 0:
                logging.info("Timestamp: {}".format(timestamp))
                logging.info("Tick: {}".format(tick))

                dump = os.path.join(SETTINGS['export_dir'],
                                    "{}.json".format(timestamp))
                nodes = json.loads(open(dump, "r").read(), encoding="latin-1")
                data, prev_nodes = get_chart_data(tick, nodes, prev_nodes)

                REDIS_CONN.set("t:m:last", json.dumps(data))
                REDIS_CONN.zadd("t:m:timestamp", tick,
                                "{}:{}".format(tick, timestamp))

    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
