#!/bin/bash
 cd data/pcap
 sudo tcpdump -i ens3 -w %s.ens3.pcap -v -n -G 2 -B 65536 -Z ubuntu 'tcp and not src host 54.208.195.206' > ens3 #2>&1 &
