#!/bin/bash
# --- bitcoin mainnet: f9beb4d9 (db = 0) ---
/usr/bin/nice -n 19 python -u crawl.py conf/crawl.f9beb4d9.conf master > log/crawl.f9beb4d9.master.out 2>&1 &
/usr/bin/nice -n 19 python -u crawl.py conf/crawl.f9beb4d9.conf slave > log/crawl.f9beb4d9.slave.1.out 2>&1 &
/usr/bin/nice -n 19 python -u crawl.py conf/crawl.f9beb4d9.conf slave > log/crawl.f9beb4d9.slave.2.out 2>&1 &
/usr/bin/nice -n 19 python -u crawl.py conf/crawl.f9beb4d9.conf slave > log/crawl.f9beb4d9.slave.3.out 2>&1 &

/usr/bin/nice -n 19 python -u ping.py conf/ping.f9beb4d9.conf master > log/ping.f9beb4d9.master.out 2>&1 &
/usr/bin/nice -n 19 python -u ping.py conf/ping.f9beb4d9.conf slave > log/ping.f9beb4d9.slave.1.out 2>&1 &
/usr/bin/nice -n 19 python -u ping.py conf/ping.f9beb4d9.conf slave > log/ping.f9beb4d9.slave.2.out 2>&1 &
/usr/bin/nice -n 19 python -u ping.py conf/ping.f9beb4d9.conf slave > log/ping.f9beb4d9.slave.3.out 2>&1 &
/usr/bin/nice -n 19 python -u ping.py conf/ping.f9beb4d9.conf slave > log/ping.f9beb4d9.slave.4.out 2>&1 &
/usr/bin/nice -n 19 python -u ping.py conf/ping.f9beb4d9.conf slave > log/ping.f9beb4d9.slave.5.out 2>&1 &
/usr/bin/nice -n 19 python -u ping.py conf/ping.f9beb4d9.conf slave > log/ping.f9beb4d9.slave.6.out 2>&1 &
/usr/bin/nice -n 19 python -u ping.py conf/ping.f9beb4d9.conf slave > log/ping.f9beb4d9.slave.7.out 2>&1 &
/usr/bin/nice -n 19 python -u ping.py conf/ping.f9beb4d9.conf slave > log/ping.f9beb4d9.slave.8.out 2>&1 &
/usr/bin/nice -n 19 python -u ping.py conf/ping.f9beb4d9.conf slave > log/ping.f9beb4d9.slave.9.out 2>&1 &
/usr/bin/nice -n 19 python -u ping.py conf/ping.f9beb4d9.conf slave > log/ping.f9beb4d9.slave.10.out 2>&1 &

/usr/bin/nice -n 19 python -u resolve.py conf/resolve.f9beb4d9.conf > log/resolve.f9beb4d9.out 2>&1 &

/usr/bin/nice -n 19 python -u export.py conf/export.f9beb4d9.conf > log/export.f9beb4d9.out 2>&1 &

/usr/bin/nice -n 19 python -u seeder.py conf/seeder.f9beb4d9.conf > log/seeder.f9beb4d9.out 2>&1 &

/usr/bin/nice -n 19 python -u cache_inv.py conf/cache_inv.f9beb4d9.conf > log/cache_inv.f9beb4d9.1.out 2>&1 &
/usr/bin/nice -n 19 python -u cache_inv.py conf/cache_inv.f9beb4d9.conf > log/cache_inv.f9beb4d9.2.out 2>&1 &
/usr/bin/nice -n 19 python -u cache_inv.py conf/cache_inv.f9beb4d9.conf > log/cache_inv.f9beb4d9.3.out 2>&1 &
