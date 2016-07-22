test_list = inotify
test_list += icmp
test_list += text_stat
test_list += xml_fetch

all:
	@for d in $(test_list); do \
		make -C $$d; \
		[ "$$?" != "0" ] && exit "$$?"; \
	done; \
	echo OK: test

pack:
	@for d in $(test_list); do \
                make -C $$d pack; \
	done
	@echo OK: test

clean:
	@for d in $(test_list); do \
		make -C $$d clean; \
	done
	@echo OK: test

