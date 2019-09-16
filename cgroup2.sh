#!/bin/sh
. /usr/lib/vmwrap/init.sh

# cgroup2
mount -t cgroup2 -o nsdelegate cgroup /sys/fs/cgroup
echo "+cpu +memory +pids" > /sys/fs/cgroup/cgroup.subtree_control
mkdir /sys/fs/cgroup/delegated
chown $vmwrap_uid:$vmwrap_gid \
    /sys/fs/cgroup/delegated \
    /sys/fs/cgroup/delegated/cgroup.subtree_control \
    /sys/fs/cgroup/delegated/cgroup.procs \
    /sys/fs/cgroup/delegated/cgroup.threads
echo $vmwrap_pid > /sys/fs/cgroup/delegated/cgroup.procs
