#!/bin/bash
python -u crawl.py crawl.conf > crawl.out 2>&1 &
python -u ping.py ping.conf > ping.out 2>&1 &
python -u resolve.py resolve.conf > resolve.out 2>&1 &
python -u export.py export.conf > export.out 2>&1 &
