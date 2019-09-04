#!/bin/sh
set -eu

# mount filesystems
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
mount -t proc proc /proc
mount -t tmpfs tmp /tmp
mount -t tmpfs run /run
mkdir /dev/shm -m1777
mount -t tmpfs shm /dev/shm

# setup /etc overlay
mkdir /tmp/etco
mount -t tmpfs none /tmp/etco
mkdir /tmp/etco/etcu /tmp/etco/etcw
mount -t overlay -o upperdir=/tmp/etco/etcu,workdir=/tmp/etco/etcw,lowerdir=/etc overlay /etc
umount /tmp/etco
rmdir /tmp/etco

# swap
if [ -n "${vmwrap_swap:-}" ]; then
  mkswap $vmwrap_swap
  swapon $vmwrap_swap
fi

# confugure network
hostname $(cat /etc/hostname)
ifconfig lo up
ifconfig eth0 10.0.2.10
ifconfig eth0 up
ip route add default via 10.0.2.2 dev eth0
rm -f /etc/resolv.conf
echo nameserver 10.0.2.3 > /etc/resolv.conf

# cgroup
# mount -t cgroup2 -o nsdelegate cgroup /sys/fs/cgroup
# echo "+cpu +memory +pids" > /sys/fs/cgroup/cgroup.subtree_control
# mkdir /sys/fs/cgroup/delegated
# chown $vmwrap_uid:$vmwrap_gid \
#   /sys/fs/cgroup/delegated \
#   /sys/fs/cgroup/delegated/cgroup.subtree_control \
#   /sys/fs/cgroup/delegated/cgroup.procs \
#   /sys/fs/cgroup/delegated/cgroup.threads
# echo $vmwrap_pid > /sys/fs/cgroup/delegated/cgroup.procs
