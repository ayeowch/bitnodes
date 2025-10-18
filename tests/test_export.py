#!/usr/bin/env python
# -*- coding: utf-8 -*-
import json
import os
import time
from unittest import mock

from export import Export, init_conf
from utils import new_redis_conn


@mock.patch("export.Export.write_json_file")
@mock.patch("export.Export.get_heights")
@mock.patch("redis.StrictRedis")
def test_export(mock_strict_redis, mock_get_heights, mock_write_json_file):
    mock_strict_redis.return_value.pipeline.return_value.execute.return_value = [
        "750000",
        None,
        None,
    ]
    mock_get_heights.return_value = {
        "54.254.244.105-8333": 750000,
    }

    timestamp = int(time.time())

    json_filepath = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "1663113591.json"
    )
    nodes = json.loads(open(json_filepath, "r").read())

    # Emulate 'opendata' set from Redis.
    nodes = [json.dumps((n[0], n[1], n[5])) for n in nodes][:10]

    conf_filepath = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "..", "conf", "export.conf.default"
    )
    init_conf(conf_filepath)

    redis_conn = new_redis_conn(db=0)

    export = Export(timestamp=timestamp, nodes=nodes, redis_conn=redis_conn)
    export.export_nodes()

    assert len(mock_write_json_file.call_args[0][0]) == 10
    assert mock_write_json_file.call_args[0][0][-1] == (
        "54.254.244.105",
        8333,
        1033,
        750000,
        None,
        "Singapore",
        "SG",
        1.2872,
        103.8507,
        "Asia/Singapore",
        "AS16509",
        "AMAZON-02",
    )
