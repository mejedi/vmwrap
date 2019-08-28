#!/bin/sh
qemu-system-x86_64 -nographic -no-reboot -enable-kvm -serial mon:stdio -cpu host \
-fsdev local,security_model=passthrough,id=fsdev0,path=/ \
-device virtio-9p-pci,id=fs0,fsdev=fsdev0,mount_tag=rootfs \
-netdev user,id=n1 -device virtio-net-pci,netdev=n1 \
-kernel bzImage -initrd initrd -append "console=ttyS0 panic=-1 vmwrap_mount=rootfs vmwrap_init=/root/init.sh"
