#!/bin/bash


sudo systemctl start crawl
sudo systemctl start crawl_slave

sudo systemctl start ping_slave
sudo systemctl start ping

sudo systemctl start resolve
sudo systemctl start export
sudo systemctl start pcap
sudo systemctl start seeder

# --- bitcoin mainnet: f9beb4d9 (db = 0) ---
# python -u crawl.py conf/crawl.f9beb4d9.conf master > log/crawl.f9beb4d9.master.out 2>&1 &
# python -u crawl.py conf/crawl.f9beb4d9.conf slave > log/crawl.f9beb4d9.slave.1.out 2>&1 &
# python -u crawl.py conf/crawl.f9beb4d9.conf slave > log/crawl.f9beb4d9.slave.2.out 2>&1 &
# python -u crawl.py conf/crawl.f9beb4d9.conf slave > log/crawl.f9beb4d9.slave.3.out 2>&1 &
# python -u crawl.py conf/crawl.f9beb4d9.conf slave > log/crawl.f9beb4d9.slave.4.out 2>&1 &

# python -u ping.py conf/ping.f9beb4d9.conf master > log/ping.f9beb4d9.master.out 2>&1 &
# python -u ping.py conf/ping.f9beb4d9.conf slave > log/ping.f9beb4d9.slave.1.out 2>&1 &
# python -u ping.py conf/ping.f9beb4d9.conf slave > log/ping.f9beb4d9.slave.2.out 2>&1 &
# python -u ping.py conf/ping.f9beb4d9.conf slave > log/ping.f9beb4d9.slave.3.out 2>&1 &
# python -u ping.py conf/ping.f9beb4d9.conf slave > log/ping.f9beb4d9.slave.4.out 2>&1 &
# python -u ping.py conf/ping.f9beb4d9.conf slave > log/ping.f9beb4d9.slave.5.out 2>&1 &
# python -u ping.py conf/ping.f9beb4d9.conf slave > log/ping.f9beb4d9.slave.6.out 2>&1 &
# python -u ping.py conf/ping.f9beb4d9.conf slave > log/ping.f9beb4d9.slave.7.out 2>&1 &
# python -u ping.py conf/ping.f9beb4d9.conf slave > log/ping.f9beb4d9.slave.8.out 2>&1 &
# python -u ping.py conf/ping.f9beb4d9.conf slave > log/ping.f9beb4d9.slave.9.out 2>&1 &

# python -u resolve.py conf/resolve.f9beb4d9.conf > log/resolve.f9beb4d9.out 2>&1 &

# python -u export.py conf/export.f9beb4d9.conf > log/export.f9beb4d9.out 2>&1 &

# python -u seeder.py conf/seeder.f9beb4d9.conf > log/seeder.f9beb4d9.out 2>&1 &

# python -u pcap.py conf/pcap.f9beb4d9.conf > log/pcap.f9beb4d9.1.out 2>&1 &
# python -u pcap.py conf/pcap.f9beb4d9.conf > log/pcap.f9beb4d9.2.out 2>&1 &
# python -u pcap.py conf/pcap.f9beb4d9.conf > log/pcap.f9beb4d9.3.out 2>&1 &

# # --- bitcoin testnet3: 0b110907 (db = 1) ---
# python -u crawl.py conf/crawl.0b110907.conf master > log/crawl.0b110907.master.out 2>&1 &
# python -u crawl.py conf/crawl.0b110907.conf slave > log/crawl.0b110907.slave.1.out 2>&1 &

# python -u ping.py conf/ping.0b110907.conf master > log/ping.0b110907.master.out 2>&1 &
# python -u ping.py conf/ping.0b110907.conf slave > log/ping.0b110907.slave.1.out 2>&1 &

# python -u resolve.py conf/resolve.0b110907.conf > log/resolve.0b110907.out 2>&1 &

# python -u export.py conf/export.0b110907.conf > log/export.0b110907.out 2>&1 &

# python -u seeder.py conf/seeder.0b110907.conf > log/seeder.0b110907.out 2>&1 &

# python -u pcap.py conf/pcap.0b110907.conf > log/pcap.0b110907.1.out 2>&1 &
# python -u pcap.py conf/pcap.0b110907.conf > log/pcap.0b110907.2.out 2>&1 &
# python -u pcap.py conf/pcap.0b110907.conf > log/pcap.0b110907.3.out 2>&1 &

# --- bitcoin cash mainnet: e3e1f3e8 (db = 2) ---
#python -u crawl.py conf/crawl.e3e1f3e8.conf master > log/crawl.e3e1f3e8.master.out 2>&1 &
#python -u crawl.py conf/crawl.e3e1f3e8.conf slave > log/crawl.e3e1f3e8.slave.1.out 2>&1 &
