![Bitnodes](https://bitnodes.io/static/img/bitnodes-github.png "Bitnodes")

Bitnodes estimates the relative size of the Bitcoin peer-to-peer network by finding all of its reachable nodes. The current methodology involves sending [getaddr](https://en.bitcoin.it/wiki/Protocol_specification#getaddr) messages recursively to find all the reachable nodes in the network, starting from a set of seed nodes. Bitnodes uses Bitcoin protocol version 70001 (i.e. >= /Satoshi:0.8.x/), so nodes running an older protocol version will be skipped.

See [Provisioning Bitcoin Network Crawler](https://github.com/ayeowch/bitnodes/wiki/Provisioning-Bitcoin-Network-Crawler) for steps on setting up a machine to run Bitnodes. The [Redis Data](https://github.com/ayeowch/bitnodes/wiki/Redis-Data) contains the list of keys and their associated values that are written by the scripts in this project. If you wish to access the data, e.g. network snapshots, collected using this project, see [API](https://bitnodes.io/api/).

### Links

* [Home](https://bitnodes.io/)

* [API](https://bitnodes.io/api/)

* [Network Snapshot](https://bitnodes.io/nodes/)

* [Charts](https://bitnodes.io/dashboard/)

* [Live Map](https://bitnodes.io/nodes/live-map/)

* [Network Map](https://bitnodes.io/nodes/network-map/)

* [Leaderboard](https://bitnodes.io/nodes/leaderboard/)

* [Client Status](https://bitnodes.io/dashboard/bitcoind/)

* [Combined Estimation](https://bitnodes.io/nodes/all/)

* [Check Your Node](https://bitnodes.io/#join-the-network)

* [What is a Bitcoin node?](https://bitnodes.io/what-is-a-bitcoin-node/)

* [Addresses List](https://bitnodes.io/nodes/addresses-list/)

### CI

[![CircleCI](https://circleci.com/gh/ayeowch/bitnodes.svg?style=svg)](https://circleci.com/gh/ayeowch/bitnodes)

### Setup

```
# Install pyenv dependencies
sudo apt update && sudo apt install make build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev wget curl llvm libncursesw5-dev xz-utils tk-dev libxml2-dev libxmlsec1-dev libffi-dev liblzma-dev

# Install pyenv
git clone https://github.com/pyenv/pyenv.git ~/.pyenv
cd ~/.pyenv && src/configure && make -C src
echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc
echo 'command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc
echo 'eval "$(pyenv init -)"' >> ~/.bashrc
echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.profile
echo 'command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.profile
echo 'eval "$(pyenv init -)"' >> ~/.profile

# Setup project
source ~/.bashrc
pyenv install 3.11.2
cd && git clone https://github.com/ayeowch/bitnodes.git && cd bitnodes
~/.pyenv/versions/3.11.2/bin/python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pytest
```

See also [Provisioning Bitcoin Network Crawler](https://github.com/ayeowch/bitnodes/wiki/Provisioning-Bitcoin-Network-Crawler).
