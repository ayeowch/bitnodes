#!/bin/bash
 cd data/pcap
 sudo tcpdump -i ens3 -w %s.ens3.pcap -v -n -G 2 -B 65536 -Z ubuntu 'tcp and not src host 34.231.133.189' > ens3 #2>&1 &
 sudo tcpdump -i lo -w %s.lo.pcap -v -n -G 2 -B 65536 -Z ubuntu 'tcp and port 9050' > lo