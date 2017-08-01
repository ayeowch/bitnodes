# This is a sketchy fork for the litecoin network

![Bitnodes](https://bitnodes.21.co/static/img/bitnodes-github.png "Bitnodes")

Bitnodes is currently being developed to estimate the size of the Bitcoin network by finding all the reachable nodes in the network. The current methodology involves sending [getaddr](https://en.bitcoin.it/wiki/Protocol_specification#getaddr) messages recursively to find all the reachable nodes in the network, starting from a set of seed nodes. Bitnodes uses Bitcoin protocol version 70001 (i.e. >= /Satoshi:0.8.x/), so nodes running an older protocol version will be skipped.

* [Network Snapshot](https://bitnodes.21.co/nodes/)

* [24-hour Charts](https://bitnodes.21.co/dashboard/)

* [Live Map](https://bitnodes.21.co/nodes/live-map/)

* [Network Map](https://bitnodes.21.co/nodes/network-map/)

* [New Transactions](https://bitnodes.21.co/dashboard/transactions/)

* [Leaderboard](https://bitnodes.21.co/nodes/leaderboard/)

See [Provisioning Bitcoin Network Crawler](https://github.com/ayeowch/bitnodes/wiki/Provisioning-Bitcoin-Network-Crawler) for steps on setting up a machine to run Bitnodes. The [Redis Data](https://github.com/ayeowch/bitnodes/wiki/Redis-Data) contains the list of keys and their associated values that are written by the scripts in this project. If you wish to access the data, e.g. network snapshots, collected using this project, see [Bitnodes API v1.0](https://bitnodes.21.co/api/).
