#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# tests.py - Dummy data and tests for bitnodes.
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
Dummy data and tests for bitnodes.
"""

import time

DUMMY_SEEDS = {
    1: "1.1.1.1",
    2: "2.2.2.2",
    3: "3.3.3.3",
    4: "4.4.4.4",
    5: "5.5.5.5",
    6: "6.6.6.6",
}


def dummy_getaddr(node):
    """
    Returns adjacent nodes based on the dummy network below:
        1.1.1.1
            2.2.2.2
                4.4.4.4
                    10.10.10.10
                    11.11.11.11
                        13.13.13.13
                            14.14.14.14
                                15.15.15.15
                                    16.16.16.16
                                        22.22.22.22
                                    17.17.17.17
                                18.18.18.18
                                    4.4.4.4
                                    5.5.5.5
                                19.19.19.19
                                20.20.20.20
                                    21.21.21.21
                    12.12.12.12
            3.3.3.3
                5.5.5.5
                    7.7.7.7
                        9.9.9.9
                    8.8.8.8
                6.6.6.6
            16.16.16.16
    """
    time.sleep(0.2)

    return {
        "1.1.1.1": [{"ip": "2.2.2.2"}, {"ip": "3.3.3.3"},
                    {"ip": "16.16.16.16"}],
        "2.2.2.2": [{"ip": "4.4.4.4"}],
        "3.3.3.3": [{"ip": "5.5.5.5"}, {"ip": "6.6.6.6"}],
        "4.4.4.4": [{"ip": "10.10.10.10"}, {"ip": "11.11.11.11"},
                    {"ip": "12.12.12.12"}],
        "5.5.5.5": [{"ip": "7.7.7.7"}, {"ip": "8.8.8.8"}],
        "6.6.6.6": [],
        "7.7.7.7": [{"ip": "9.9.9.9"}],
        "8.8.8.8": [],
        "9.9.9.9": [],
        "10.10.10.10": [],
        "11.11.11.11": [{"ip": "13.13.13.13"}],
        "12.12.12.12": [],
        "13.13.13.13": [{"ip": "14.14.14.14"}],
        "14.14.14.14": [{"ip": "15.15.15.15"}, {"ip": "18.18.18.18"},
                        {"ip": "19.19.19.19"}, {"ip": "20.20.20.20"}],
        "15.15.15.15": [{"ip": "16.16.16.16"}, {"ip": "17.17.17.17"}],
        "16.16.16.16": [{"ip": "22.22.22.22"}],
        "17.17.17.17": [],
        "18.18.18.18": [{"ip": "4.4.4.4"}, {"ip": "5.5.5.5"}],
        "19.19.19.19": [],
        "20.20.20.20": [{"ip": "21.21.21.21"}],
        "21.21.21.21": [],
        "22.22.22.22": [],
    }.get(node, [])
