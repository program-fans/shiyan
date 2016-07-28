#kernel modules
app_list = modules

#libs
app_list += wf_lib
app_list += ghttp_lib
app_list += mxml_lib

#programs
app_list += sock_raw
app_list += admin
app_list += arp
app_list += api_store
app_list += speedtest
app_list += netscan
app_list += tickets

app_list += reptile

#test programs
app_list += test

.PHONY:all

all:
	@for d in $(app_list); do \
		make -C $$d; \
		[ "$$?" != "0" ] && exit "$$?"; \
	done; \
	echo OK: done

pack:
	@for d in $(app_list); do \
                make -C $$d pack; \
	done
	zip -qr wolf_shiyan.zip ./
	@echo OK: wolf_shiyan.zip

clean:
	@for d in $(app_list); do \
                make -C $$d clean; \
	done
	rm -f *.order *.symvers
	@echo OK: done

