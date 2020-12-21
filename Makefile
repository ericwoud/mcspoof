EXTRA_CFLAGS := -I/usr/include

obj-m += mcspoof.o

ifndef KDIR
KDIR=/lib/modules/$(shell uname -r)/build
endif

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install:
	mkdir -p /lib/modules/$(shell uname -r)/extra
	cp -f ./mcspoof.ko /lib/modules/$(shell uname -r)/extra/
	depmod -a

remove:
	rm -f /lib/modules/$(shell uname -r)/extra/mcspoof.ko
	depmod -a

