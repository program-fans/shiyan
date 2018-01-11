TAR=wf

obj-m=$(TAR).o
#wf-objs=wf_ko.o

KERNELBUILD=/lib/modules/$(shell uname -r)/build/

default:
	make -C $(KERNELBUILD) BUILDDIR=$(CURDIR) SUBDIRS=$(CURDIR) modules
#make -C $(KERNELBUILD) V=1 ARCH=$(ARCH) BUILDDIR=$(CURDIR) SUBDIRS=$(CURDIR) modules

install:
	insmod $(TAR).ko

uninstall:
	rmmod $(TAR)

clean:
	rm -f *.o *.rc .*.o.d *.ko *.mod.c *.order .*.cmd *.symvers
	rm -rf .tmp_versions
