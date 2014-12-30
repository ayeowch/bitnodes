# Bitnodes
Bitnodes is currently being developed to estimate the size of the Bitcoin network by finding all the reachable nodes in the network. The current methodology involves sending [getaddr](https://en.bitcoin.it/wiki/Protocol_specification#getaddr) messages recursively to find all the reachable nodes in the network, starting from a set of seed nodes. Bitnodes uses Bitcoin protocol version 70001 (i.e. >= /Satoshi:0.8.x/), so nodes running an older protocol version will be skipped.

## Setup
See [Provisioning Bitcoin Network Crawler](https://github.com/ayeowch/bitnodes/wiki/Provisioning-Bitcoin-Network-Crawler)

BITNODES TAKES UP ONE CONNECTION SLOT FROM EACH REACHABLE NODE IN THE NETWORK. IF YOU INTEND TO USE BITNODES TO CRAWL THE NETWORK, PLEASE CONSIDER RUNNING ONLY 1 INSTANCE OF THE CRAWLER TO AVOID TAKING UP THE VALUABLE CONNECTION SLOTS FROM EACH NODE.
