ifeq ($(shell which klcc),)
  init:CFLAGS = -static
else
  init:CC = klcc
endif

all: initrd vmwrap

initrd: init
	echo init | cpio --quiet -H newc -o | gzip -9 -n >initrd

init: init.c
	${CC} ${CFLAGS} init.c -o init
	strip init
