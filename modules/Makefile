mlist = wf
mlist = scull

all:
	@for d in $(mlist); do \
		make -C $$d; \
		[ "$$?" != "0" ] && exit "$$?"; \
	done; \
	echo OK: modules

clean:
	@for d in $(mlist); do \
		make -C $$d clean; \
		[ "$$?" != "0" ] && exit "$$?"; \
	done; \
	echo OK: modules

install:
	@for d in $(mlist); do \
		make -C $$d install; \
		[ "$$?" != "0" ] && exit "$$?"; \
	done; \
	echo OK: modules

uninstall:
	@for d in $(mlist); do \
		make -C $$d uninstall; \
		[ "$$?" != "0" ] && exit "$$?"; \
	done; \
	echo OK: modules

