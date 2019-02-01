obj-m = module2.o

KERNEL_SRC := bspv1.1.0/linux_v3.8.7/work
KERNEL_SOURCE := linux-toradex

all:
	make ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) -C $(KERNEL_SOURCE) M=$(shell pwd) modules
clean:
	make -C $(KERNEL_SOURCE) M=$(shell pwd) clean

