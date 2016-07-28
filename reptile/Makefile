NAME = reptile

list = sinatech_reptile
list += douban_reptile

all:
	@for d in $(list); do \
		make -C $$d; \
		[ "$$?" != "0" ] && exit "$$?"; \
	done; \
	echo OK: $(NAME)

pack:
	@for d in $(list); do \
                make -C $$d pack; \
	done
	@echo OK: $(NAME)

clean:
	@for d in $(list); do \
		make -C $$d clean; \
	done
	@echo OK: $(NAME)

