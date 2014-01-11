#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# chart.py - Stores chart data from Bitcoin network pinger.
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
Stores chart data from Bitcoin network pinger.
"""

import glob
import json
import logging
import os
import redis
import sys
import threading

# Global instance of Redis connection
REDIS_CONN = redis.StrictRedis()

# Minimum chart interval, i.e. seconds between 2 ticks
INTERVAL = 600


def get_chart_data(nodes, prev_nodes):
    """
    Generates chart data for current tick using enumerated data for all
    reachable nodes.
    """
    data = {
        'nodes': len(nodes),
        'ipv4': 0,
        'ipv6': 0,
        'user_agents': {},
        'cities': {},
        'countries': {},
        'timezones': {},
        'orgs': {},
        'join': 0,
        'leave': 0,
    }
    curr_nodes = set()

    for node in nodes:
        #  0: address
        #  1: port
        #  2: version
        #  3: user_agent
        #  4: timestamp
        #  5: start_height
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
        city = node[7]
        country = node[8]
        timezone = node[11]
        org = node[13]

        curr_nodes.add((address, port))

        if ":" in address:
            data['ipv6'] += 1
        else:
            data['ipv4'] += 1

        data['user_agents'][user_agent] = data['user_agents'].get(
            user_agent, 0) + 1

        city = "%s, %s" % (city, country)
        data['cities'][city] = data['cities'].get(city, 0) + 1

        data['countries'][country] = data['countries'].get(country, 0) + 1
        data['timezones'][timezone] = data['timezones'].get(timezone, 0) + 1
        data['orgs'][org] = data['orgs'].get(org, 0) + 1

    data['join'] = len(curr_nodes - prev_nodes)
    data['leave'] = len(prev_nodes - curr_nodes)

    return data, curr_nodes


def save_chart_data(data, timestamp, tick):
    """
    Saves chart data for current tick in a timestamp-prefixed JSON file and
    updates the time series data in Redis.
    """
    chart_dir = "data/chart"
    if not os.path.exists(chart_dir):
        os.makedirs(chart_dir)

    dump = os.path.join(chart_dir, "{}.json".format(tick))
    open(dump, 'w').write(json.dumps(data))
    logging.info("Wrote {}".format(dump))

    redis_pipe = REDIS_CONN.pipeline()
    redis_pipe.zadd("t:m:timestamp", tick, "{}:{}".format(tick, timestamp))
    redis_pipe.zadd("t:m:nodes", tick, "{}:{}".format(tick, data['nodes']))
    redis_pipe.zadd("t:m:ipv4", tick, "{}:{}".format(tick, data['ipv4']))
    redis_pipe.zadd("t:m:ipv6", tick, "{}:{}".format(tick, data['ipv6']))

    for user_agent in data['user_agents'].items():
        key = "t:m:user_agent:%s" % user_agent[0]
        redis_pipe.zadd(key, tick, "{}:{}".format(tick, user_agent[1]))

    for city in data['cities'].items():
        key = "t:m:city:%s" % city[0]
        redis_pipe.zadd(key, tick, "{}:{}".format(tick, city[1]))

    for country in data['countries'].items():
        key = "t:m:country:%s" % country[0]
        redis_pipe.zadd(key, tick, "{}:{}".format(tick, country[1]))

    for timezone in data['timezones'].items():
        key = "t:m:timezone:%s" % timezone[0]
        redis_pipe.zadd(key, tick, "{}:{}".format(tick, timezone[1]))

    for org in data['orgs'].items():
        key = "t:m:org:%s" % org[0]
        redis_pipe.zadd(key, tick, "{}:{}".format(tick, org[1]))

    redis_pipe.zadd("t:m:join", tick, "{}:{}".format(tick, data['join']))
    redis_pipe.zadd("t:m:leave", tick, "{}:{}".format(tick, data['leave']))

    redis_pipe.execute()


def replay():
    """
    Removes chart data and replays the published timestamps from export.py to
    recreate chart data.
    """
    keys = REDIS_CONN.keys('t:*')
    redis_pipe = REDIS_CONN.pipeline()
    for key in keys:
        redis_pipe.delete(key)
    redis_pipe.execute()

    files = sorted(glob.iglob("data/export/*.json"), key=os.path.getctime)
    for dump in files:
        timestamp = os.path.basename(dump).rstrip(".json")
        REDIS_CONN.publish('export', timestamp)


def main():
    logfile = os.path.basename(__file__).replace(".py", ".log")
    loglevel = logging.INFO
    logformat = ("%(asctime)s,%(msecs)05.1f %(levelname)s (%(funcName)s) "
                 "%(message)s")
    logging.basicConfig(level=loglevel,
                        format=logformat,
                        filename=logfile,
                        filemode='w')
    print("Writing output to {}, press CTRL+C to terminate..".format(logfile))

    threading.Thread(target=replay).start()

    prev_nodes = set()

    pubsub = REDIS_CONN.pubsub()
    pubsub.subscribe('export')
    for msg in pubsub.listen():
        # 'export' message is published by export.py after exporting enumerated
        # data for all reachable nodes.
        if msg['channel'] == 'export' and msg['type'] == 'message':
            timestamp = int(msg['data'])  # From ping.py's 'snapshot' message
            tick = timestamp - (timestamp % INTERVAL)
            logging.info("Timestamp: {}".format(timestamp))
            logging.info("Tick: {}".format(tick))

            # Only the first snapshot before the next interval is used to
            # generate the chart data for each tick.
            if REDIS_CONN.zcount("t:m:nodes", tick, tick) == 0:
                dump = "data/export/{}.json".format(timestamp)
                nodes = json.loads(open(dump, "r").read(), encoding="latin-1")
                data, prev_nodes = get_chart_data(nodes, prev_nodes)
                save_chart_data(data, timestamp, tick)
                REDIS_CONN.publish('chart', tick)

    return 0


if __name__ == '__main__':
    sys.exit(main())
