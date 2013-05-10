# Bitnodes
Bitnodes is a Python script written to estimate the size of the Bitcoin network by finding all the peering nodes in the network.

## Methodology
The current methodology involves sending [getaddr](https://en.bitcoin.it/wiki/Protocol_specification#getaddr) message recursively to find all the peering nodes in the network starting from a set of seed nodes. Bitnodes uses Bitcoin protocol version 70001, so peers connected to a node with older protocol version will be skipped.

## Requirements
* Python 2.7
* dig (or equivalent utility)

## Usage
The default configuration in config.cfg should work for most users. To run Bitnodes:

    $ python bitnodes.py config.cfg
    Writing output to bitnodes.log, press CTRL+C to terminate..

Newly discovered nodes will be added into the SQLite database called bitnodes.db in the `nodes` table. Tail the logfile to see the current status:

    $ tail -f bitnodes.log
    INFO 2013-05-10 05:29:11,435 1952 Starting bitnodes with 188 seed nodes
    INFO 2013-05-10 05:30:14,494 1969 Found 351 nodes
    INFO 2013-05-10 05:31:35,726 1969 Found 767 nodes
    INFO 2013-05-10 05:32:47,370 1969 Found 1114 nodes
    INFO 2013-05-10 05:33:47,530 1969 Found 1435 nodes
    INFO 2013-05-10 05:34:48,635 1969 Found 1816 nodes
    INFO 2013-05-10 05:35:48,948 1969 Found 2170 nodes
    INFO 2013-05-10 05:36:49,278 1969 Found 2534 nodes
    ..

## License
Copyright (c) 2013 Addy Yeow Chin Heng &lt;ayeowch@gmail.com&gt;

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
