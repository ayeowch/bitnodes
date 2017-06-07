#!/bin/bash
# --- mainnet ---
python -u crawl.py crawl.mainnet.conf master > crawl.mainnet.master.out 2>&1 &
python -u crawl.py crawl.mainnet.conf slave > crawl.mainnet.slave.1.out 2>&1 &
python -u crawl.py crawl.mainnet.conf slave > crawl.mainnet.slave.2.out 2>&1 &
python -u crawl.py crawl.mainnet.conf slave > crawl.mainnet.slave.3.out 2>&1 &
python -u crawl.py crawl.mainnet.conf slave > crawl.mainnet.slave.4.out 2>&1 &

python -u ping.py ping.conf master > ping.master.out 2>&1 &
python -u ping.py ping.conf slave > ping.slave.1.out 2>&1 &
python -u ping.py ping.conf slave > ping.slave.2.out 2>&1 &
python -u ping.py ping.conf slave > ping.slave.3.out 2>&1 &
python -u ping.py ping.conf slave > ping.slave.4.out 2>&1 &
python -u ping.py ping.conf slave > ping.slave.5.out 2>&1 &
python -u ping.py ping.conf slave > ping.slave.6.out 2>&1 &
python -u ping.py ping.conf slave > ping.slave.7.out 2>&1 &
python -u ping.py ping.conf slave > ping.slave.8.out 2>&1 &
python -u ping.py ping.conf slave > ping.slave.9.out 2>&1 &

python -u resolve.py resolve.conf > resolve.out 2>&1 &

python -u export.py export.conf > export.out 2>&1 &

python -u seeder.py seeder.conf > seeder.out 2>&1 &

python -u pcap.py pcap.conf > pcap.1.out 2>&1 &
python -u pcap.py pcap.conf > pcap.2.out 2>&1 &
python -u pcap.py pcap.conf > pcap.3.out 2>&1 &

# --- testnet3 ---
python -u crawl.py crawl.testnet3.conf master > crawl.testnet3.master.out 2>&1 &
