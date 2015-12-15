app_list = wf_lib
app_list += ghttp_lib
app_list += sock_raw
app_list += admin
app_list += arp
app_list += cgi_test

all:
	for d in $(app_list); do \
		make -C $$d; \
		[ "$$?" != "0" ] && exit "$$?"; \
	done; \
	echo OK 

pack:
	for d in $(app_list); do \
                make -C $$d pack; \
		[ "$$?" != "0" ] && exit "$$?"; \
	done; \
	zip -qr wolf_shiyan.zip ./

clean:
	for d in $(app_list); do \
                make -C $$d clean; \
	done

