EXTRA_CFLAGS := -I/usr/include

obj-m += mcspoof.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

install:
	mkdir -p /lib/modules/$(shell uname -r)/extra
	cp -f ./mcspoof.ko /lib/modules/$(shell uname -r)/extra/
	depmod -a

remove:
	rm -f /lib/modules/$(shell uname -r)/extra/mcspoof.ko
	depmod -a

