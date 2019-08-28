all: initrd vmwrap

initrd: init
	echo init | cpio --quiet -H newc -o | gzip -9 -n >initrd

init: init.c
	klcc ${CFLAGS} init.c -o init
	strip init
