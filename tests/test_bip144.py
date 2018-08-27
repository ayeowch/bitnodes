#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
from binascii import hexlify, unhexlify
from collections import defaultdict
from Queue import PriorityQueue

from pcap import Stream, Cache
from protocol import Serializer


class Reader(Cache):
    def __init__(self, filepath):
        self.filepath = filepath
        self.serializer = Serializer(magic_number=unhexlify('f9beb4d9'))
        self.streams = defaultdict(PriorityQueue)
        self.stream = Stream()


def test_bip144():
    filepath = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), 'data', 'bip144.pcap')

    reader = Reader(filepath=filepath)
    reader.extract_streams()
    msgs = []

    for stream_id, reader.stream.segments in reader.streams.iteritems():
        assert stream_id == ('1.1.1.1', 56691, '2.2.2.2', 8333)
        msg, _ = reader.serializer.deserialize_msg(reader.stream.data().next())
        msgs.append(msg)

    assert len(msgs) == 1

    keys = sorted(msgs[0].keys())
    assert keys == [
        'checksum',
        'command',
        'length',
        'lock_time',
        'magic_number',
        'tx_hash',
        'tx_in',
        'tx_in_count',
        'tx_out',
        'tx_out_count',
        'version',
    ]

    sig = hexlify(msgs[0]['tx_in'][0]['wits'][0]).decode()
    pub = hexlify(msgs[0]['tx_in'][0]['wits'][1]).decode()

    assert (
        sig ==
        '30440220643f9527d1d226bb25321e85fa4c2e13afcc2ccfb14bc069642ec51efd5c7'
        'b430220752a1d43350d5014559eb8d57fb5d48f1e759d120fc5e0dd6f26769b1d7951'
        'c701')

    assert (
        pub ==
        '03bf91e659ba26545fe7b04b48ca3b77c624993caed10e6fdb177fba33b25230d2')
