#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
from unittest import mock

from seeder import Seeder
from seeder import init_conf


@mock.patch('seeder.Seeder.save_zone_file')
@mock.patch('seeder.Seeder.get_consensus_height')
def test_seeder(mock_get_consensus_height, mock_save_zone_file):
    mock_get_consensus_height.return_value = 754002

    conf_filepath = os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        '..',
        'conf',
        'seeder.conf.default')
    init_conf(conf_filepath)

    json_filepath = os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        'data',
        '1663113591.json')

    seeder = Seeder()
    seeder.export_nodes(json_filepath)
    assert mock_save_zone_file.call_count == 19
