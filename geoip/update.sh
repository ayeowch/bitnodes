#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
USER_AGENT="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.63 Safari/537.36"

cd $DIR

wget --user-agent="$USER_AGENT" http://geolite.maxmind.com/download/geoip/database/GeoLiteCountry/GeoIP.dat.gz
wget --user-agent="$USER_AGENT" http://geolite.maxmind.com/download/geoip/database/GeoIPv6.dat.gz
wget --user-agent="$USER_AGENT" http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz
wget --user-agent="$USER_AGENT" http://geolite.maxmind.com/download/geoip/database/GeoLiteCityv6-beta/GeoLiteCityv6.dat.gz
wget --user-agent="$USER_AGENT" http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNum.dat.gz
wget --user-agent="$USER_AGENT" http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNumv6.dat.gz

gzip -f -d GeoIP.dat.gz
gzip -f -d GeoIPv6.dat.gz
gzip -f -d GeoLiteCity.dat.gz
gzip -f -d GeoLiteCityv6.dat.gz
gzip -f -d GeoIPASNum.dat.gz
gzip -f -d GeoIPASNumv6.dat.gz
