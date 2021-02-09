#!/bin/bash

# This script cleans up all the files installed by Inspektor Gadget

# OCI hooks
for i in ocihookgadget prestart.sh poststop.sh ; do
  rm -f /host/opt/hooks/oci/$i
done

# CRIO hooks
rm -f /host/usr/share/containers/oci/hooks.d/gadget-prestart.json
rm -f /host/usr/share/containers/oci/hooks.d/gadget-poststop.json

# ld preload support
if [ -f "/host/etc/ld.so.preload" ] ; then
  # remove entry in /host/etc/ld.so.preload
  sed -i '/\/opt\/hooks\/runc\/runchooks.so/d' "/host/etc/ld.so.preload"
fi

rm -f /host/opt/hooks/runc/runchooks.so
rm -f /host/opt/hooks/runc/add-hooks.jq

# nri
if [ -f "/host/etc/nri/conf.json" ] ; then
  jq 'del(.plugins[] | select(.type == "nrigadget"))' /host/etc/nri/conf.json > /tmp/conf.json
  if [ $(jq '.plugins | length' /tmp/conf.json) == 0 ] ; then
    rm -f /host/etc/nri/conf.json
  else
    mv /tmp/conf.json /host/etc/nri/conf.json
  fi
fi

rm -f /host/opt/nri/bin/nrigadget

echo "Cleanup completed"
