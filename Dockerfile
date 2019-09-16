FROM alpine AS builder
RUN apk update && apk upgrade && apk add alpine-sdk linux-headers flex bison curl
RUN curl https://mirrors.edge.kernel.org/pub/linux/kernel/v5.x/linux-5.2.5.tar.xz | unxz | tar -x -C /root
COPY vmwrap.config /root/linux-5.2.5/.config
RUN cd /root/linux-5.2.5 && make -j $(nproc)
COPY patches /root/linux-5.2.5/patches
RUN cd /root/linux-5.2.5 && \
    patch -si patches/fs_9p_vfs_inode_dotl.c.patch fs/9p/vfs_inode_dotl.c && \
    make -j $(nproc)
COPY . /root/vmwrap
RUN cd /root/vmwrap \
  && make \
  && DESTDIR=/root/dist make install \
  && install /root/linux-5.2.5/arch/x86_64/boot/bzImage /root/dist/usr/lib/vmwrap/kernel/default

FROM scratch AS vmwrap-dist
COPY --from=builder /root/dist /

FROM alpine AS vmwrap
RUN apk update && apk upgrade && apk add qemu-system-x86_64
COPY --from=vmwrap-dist / /
