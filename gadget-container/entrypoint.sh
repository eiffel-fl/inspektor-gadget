#!/bin/bash

set -e

if [ ! -r /host/etc/os-release ] ; then
  echo "$0 must be executed in a pod with access to the host via /host" >&2
  exit 1
fi

echo -n "OS detected: "
grep PRETTY_NAME= /host/etc/os-release|cut -d= -f2-

echo -n "Kernel detected: "
uname -r

echo -n "bcc detected: "
dpkg-query --show libbcc|awk '{print $2}'

echo -n "Gadget image: "
echo $TRACELOOP_IMAGE

echo "Deployment options:"
env | grep '^INSPEKTOR_GADGET_OPTION_.*='

echo -n "Inspektor Gadget version: "
echo $INSPEKTOR_GADGET_VERSION

# gobpf currently uses global kprobes via debugfs/tracefs and not the Perf
# Event file descriptor based kprobe (Linux >=4.17). So unfortunately, kprobes
# can remain from previous executions. Ideally, gobpf should implement Perf
# Event based kprobe and fallback to debugfs/tracefs, like bcc:
# https://github.com/iovisor/bcc/blob/6e9b4509fc7a063302b574520bac6d49b01ca97e/src/cc/libbpf.c#L1021-L1027
# Meanwhile, as a workaround, delete probes manually.
# See: https://github.com/iovisor/gobpf/issues/223
echo "-:pfree_uts_ns" >> /sys/kernel/debug/tracing/kprobe_events 2>/dev/null || true
echo "-:pcap_capable" >> /sys/kernel/debug/tracing/kprobe_events 2>/dev/null || true

CRIO=0
if grep -q '^1:name=systemd:.*/crio-[0-9a-f]*\.scope$' /proc/self/cgroup > /dev/null ; then
    echo "CRI-O detected."
    CRIO=1
fi

if grep -q '^ID="rhcos"$' /host/etc/os-release > /dev/null ; then
  if [ ! -d "/host/usr/src/kernels/$(uname -r)" ] ; then
    echo "Fetching kernel-devel from CentOS 8."
    REPO=http://mirror.centos.org/centos/8/BaseOS/x86_64/os/Packages/
    RPM=kernel-devel-$(uname -r).rpm
    RPMDIR=/opt/gadget-kernel/
    RPMHOSTDIR=/host${RPMDIR}
    mkdir -p $RPMHOSTDIR/usr/src/kernels/
    test -r $RPMHOSTDIR/$RPM || \
        curl -fsSLo $RPMHOSTDIR/$RPM $REPO/$RPM
    test -r $RPMHOSTDIR/usr/src/kernels/`uname -r`/.config || \
        chroot /host sh -c "cd $RPMDIR && rpm2cpio $RPM | cpio -i"
    test ! -L /usr/src || rm -f /usr/src
    mkdir -p /usr/src/kernels/`uname -r`/
    mount --bind $RPMHOSTDIR/usr/src/kernels/`uname -r` /usr/src/kernels/`uname -r`
  fi
fi

## Hooks Begins ##

# Choose what hook mode to use based on the configuration detected
HOOK_MODE="$INSPEKTOR_GADGET_OPTION_HOOK_MODE"

if [ "$HOOK_MODE" = "auto" ] || [ -z "$HOOK_MODE" ] ; then
  if [ "$CRIO" = 1 ] ; then
    echo "hook mode cri-o detected."
    HOOK_MODE="crio"
  else
    HOOK_MODE="podinformer"
    echo "Falling back to podinformer hook."
  fi
fi

if [ "$HOOK_MODE" = "ldpreload" ] ; then
  echo "Installing ld.so.preload with runchooks.so for OCI hooks"
  mkdir -p /host/opt/hooks/runc/
  cp /opt/hooks/runc/runchooks.so /host/opt/hooks/runc/
  cp /opt/hooks/runc/add-hooks.jq /host/opt/hooks/runc/
  touch /host/etc/ld.so.preload
  if grep -q ^/opt/hooks/runc/runchooks.so$ /host/etc/ld.so.preload > /dev/null ; then
    echo "runchooks.so already setup in /etc/ld.so.preload"
  else
    echo "/opt/hooks/runc/runchooks.so" >> /host/etc/ld.so.preload
  fi
fi

if [ "$HOOK_MODE" = "crio" ] || [ "$HOOK_MODE" = "ldpreload" ] ; then
  echo "Installing hooks scripts on host..."

  mkdir -p /host/opt/hooks/oci/
  for i in ocihookgadget prestart.sh poststop.sh ; do
    echo "Installing $i..."
    cp /opt/hooks/oci/$i /host/opt/hooks/oci/
  done

  if [ "$HOOK_MODE" = "crio" ] ; then
    echo "Installing OCI hooks configuration in /usr/share/containers/oci/hooks.d"
    mkdir -p /host/usr/share/containers/oci/hooks.d
    cp /opt/hooks/crio/gadget-prestart.json /host/usr/share/containers/oci/hooks.d/gadget-prestart.json
    cp /opt/hooks/crio/gadget-poststop.json /host/usr/share/containers/oci/hooks.d/gadget-poststop.json
  fi

  echo "Hooks installation done"
fi

if [ "$HOOK_MODE" = "nri" ] ; then
  echo "Installing NRI hooks"

  # first install the binary
  mkdir -p /host/opt/nri/bin/
  cp /opt/hooks/nri/nrigadget /host/opt/nri/bin/

  # then install the configuration
  # if the configuration already exists append a new plugin
  if [ -f "/host/etc/nri/conf.json" ] ; then
    jq '.plugins += [{"type": "nrigadget"}]' /host/etc/nri/conf.json > /tmp/conf.json
    mv /tmp/conf.json /host/etc/nri/conf.json
  else
    mkdir -p /host/etc/nri/
    cp /opt/hooks/nri/conf.json /host/etc/nri/
  fi
fi

POD_INFORMER_PARAM=""
if [ "$HOOK_MODE" = "podinformer" ] ; then
  POD_INFORMER_PARAM="-podinformer"
fi

## Hooks Ends ##

echo "Starting the Gadget Tracer Manager in the background..."
rm -f /run/gadgettracermanager.socket
/bin/gadgettracermanager -serve $POD_INFORMER_PARAM &

if [ "$INSPEKTOR_GADGET_OPTION_TRACELOOP" = "true" ] ; then
  rm -f /run/traceloop.socket
  if [ "$INSPEKTOR_GADGET_OPTION_TRACELOOP_LOGLEVEL" != "" ] ; then
    exec /bin/traceloop -log "$INSPEKTOR_GADGET_OPTION_TRACELOOP_LOGLEVEL" k8s
  else
    exec /bin/traceloop k8s
  fi
fi

echo "Ready."
sleep infinity
