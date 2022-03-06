![Bitnodes](https://bitnodes.io/static/img/bitnodes-github.png "Bitnodes")

Bitnodes estimates the relative size of the Bitcoin peer-to-peer network by finding all of its reachable nodes. The current methodology involves sending [getaddr](https://en.bitcoin.it/wiki/Protocol_specification#getaddr) messages recursively to find all the reachable nodes in the network, starting from a set of seed nodes. Bitnodes uses Bitcoin protocol version 70001 (i.e. >= /Satoshi:0.8.x/), so nodes running an older protocol version will be skipped.

* [Bitnodes](https://bitnodes.io/)

* [API](https://bitnodes.io/api/)

* [Network Snapshot](https://bitnodes.io/nodes/)

* [Charts](https://bitnodes.io/dashboard/)

* [Live Map](https://bitnodes.io/nodes/live-map/)

* [Network Map](https://bitnodes.io/nodes/network-map/)

* [Leaderboard](https://bitnodes.io/nodes/leaderboard/)

* [Node Status](https://bitnodes.io/dashboard/bitcoind/)

* [What is a Bitcoin node?](https://bitnodes.io/bitcoin-node/)

* [Check if your node is accepting incoming connections](https://bitnodes.io/#join-the-network)

See [Provisioning Bitcoin Network Crawler](https://github.com/ayeowch/bitnodes/wiki/Provisioning-Bitcoin-Network-Crawler) for steps on setting up a machine to run Bitnodes. The [Redis Data](https://github.com/ayeowch/bitnodes/wiki/Redis-Data) contains the list of keys and their associated values that are written by the scripts in this project. If you wish to access the data, e.g. network snapshots, collected using this project, see [Bitnodes API v1.0](https://bitnodes.io/api/).

[![CircleCI](https://circleci.com/gh/ayeowch/bitnodes.svg?style=svg)](https://circleci.com/gh/ayeowch/bitnodes)
