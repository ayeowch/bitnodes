#!/bin/bash
sudo systemctl stop crawl_slave
sudo systemctl stop crawl


sudo systemctl stop ping_slave
sudo systemctl stop ping

sudo systemctl stop pcap
sudo systemctl stop resolve
sudo systemctl stop seeder
sudo systemctl stop export

redis-cli flushdb
rm data/crawl/mainnet/*.json
rm data/export/*.json
rm data/pcap/*.pcap

rm *.log