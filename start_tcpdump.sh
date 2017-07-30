#!/bin/bash
 cd data/pcap
 sudo tcpdump -i eth0 -w %s.eth0.pcap -v -n -G 2 -B 65536 -Z ubuntu 'tcp and not src host 54.208.195.206' > eth0 #2>&1 &