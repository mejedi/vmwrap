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
mkdir /dev/pts
mount -t devpts devpts /dev/pts

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
ifconfig eth0 $vmwrap_addr
ifconfig eth0 up
ip route add default via $vmwrap_gateway dev eth0
rm -f /etc/resolv.conf
echo nameserver $vmwrap_dns > /etc/resolv.conf
