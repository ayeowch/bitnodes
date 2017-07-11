#!/bin/bash
# --- mainnet ---
python -u crawl.py crawl.conf.default master >> log.out 2>&1 &
python -u crawl.py crawl.conf.default slave >> log.out 2>&1 &
# python -u crawl.py crawl.conf.default slave > crawl.mainnet.slave.2.out 2>&1 &
# python -u crawl.py crawl.conf.default slave > crawl.mainnet.slave.3.out 2>&1 &
# python -u crawl.py crawl.conf.default slave > crawl.mainnet.slave.4.out 2>&1 &

python -u ping.py ping.conf.default master >> log.out 2>&1 &
python -u ping.py ping.conf.default slave >> log.out 2>&1 &
python -u ping.py ping.conf.default slave >> log.out 2>&1 &
# python -u ping.py ping.conf slave > ping.slave.3.out 2>&1 &
# python -u ping.py ping.conf slave > ping.slave.4.out 2>&1 &
# python -u ping.py ping.conf slave > ping.slave.5.out 2>&1 &
# python -u ping.py ping.conf slave > ping.slave.6.out 2>&1 &
# python -u ping.py ping.conf slave > ping.slave.7.out 2>&1 &
# python -u ping.py ping.conf slave > ping.slave.8.out 2>&1 &
# python -u ping.py ping.conf slave > ping.slave.9.out 2>&1 &

python -u resolve.py resolve.conf.default >> log.out 2>&1 &

python -u export.py export.conf.default >> log.out 2>&1 &

python -u seeder.py seeder.conf.default >> log.out 2>&1 &

python -u pcap.py pcap.conf.default >> log.out 2>&1 &
python -u pcap.py pcap.conf.default >> log.out 2>&1 &
python -u pcap.py pcap.conf.default >> log.out 2>&1 &

# --- testnet3 ---
#python -u crawl.py crawl.testnet3.conf master > crawl.testnet3.master.out 2>&1 &

# cd data/pcap
# sudo tcpdump -i eth0 -w %s.eth0.pcap -v -n -G 2 -B 65536 -Z ubuntu 'tcp and not src host 54.208.195.206' > eth0 2>&1 &
# sudo tcpdump -i lo -w %s.lo.pcap -v -n -G 2 -B 65536 -Z ubuntu 'tcp and port 9050' > lo 2>&1 &