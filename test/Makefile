test_list += inotify

all:
	for d in $(test_list); do \
		make -C $$d; \
		[ "$$?" != "0" ] && exit "$$?"; \
	done; \
	echo OK: test

pack:
	for d in $(test_list); do \
                make -C $$d pack; \
		[ "$$?" != "0" ] && exit "$$?"; \
	done; \
	echo OK: test

clean:
	for d in $(test_list); do \
                make -C $$d clean; \
	done
	echo OK: test

