#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
USER_AGENT="Mozilla/5.0"

cd $DIR

if [ ! -f ".maxmind_license_key" ]; then
    echo "Missing .maxmind_license_key file. Please make sure it exists in $DIR and contains your MaxMind license key: https://support.maxmind.com/hc/en-us/sections/1260801610490-Manage-my-License-Keys"
    exit 1
fi

MAXMIND_LICENSE_KEY=$(<.maxmind_license_key)
wget --quiet --user-agent="$USER_AGENT" "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&suffix=tar.gz&license_key=$MAXMIND_LICENSE_KEY" -O GeoLite2-City.tar.gz && tar --strip-components=1 -zxf GeoLite2-City.tar.gz && rm GeoLite2-City.tar.gz
wget --quiet --user-agent="$USER_AGENT" "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&suffix=tar.gz&license_key=$MAXMIND_LICENSE_KEY" -O GeoLite2-Country.tar.gz && tar --strip-components=1 -zxf GeoLite2-Country.tar.gz && rm GeoLite2-Country.tar.gz
wget --quiet --user-agent="$USER_AGENT" "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&suffix=tar.gz&license_key=$MAXMIND_LICENSE_KEY" -O GeoLite2-ASN.tar.gz && tar --strip-components=1 -zxf GeoLite2-ASN.tar.gz && rm GeoLite2-ASN.tar.gz
rm *.txt
