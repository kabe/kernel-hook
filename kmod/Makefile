#INCDIR=/usr/src/linux-headers-2.6.32-5-common/include/
KERNELSRCDIR = /usr/src/linux
BUILD_DIR := $(shell pwd)
VERBOSE = 0

obj-m := kernelhook.o

kernelhook-objs := kernel-hook.o

#CFLAGS=-I$(INCDIR)

all : $(TARGETS)
	make -C $(KERNELSRCDIR) SUBDIRS=$(BUILD_DIR) KBUILD_VERBOSE=$(VERBOSE) modules
	cp kernelhook.ko /tmp/


#kernel-hook.o : kernel-hook.c


clean :
	-$(RM) *.o
	-$(RM) *~ *.mod.c
	-$(RM) *.ko
	-$(RM) *.order *.symvers

