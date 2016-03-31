app_list += modules
app_list = wf_lib
app_list += ghttp_lib
app_list += mxml_lib
app_list += sock_raw
app_list += admin
app_list += arp
app_list += api_store

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
	echo OK: wolf_shiyan.zip

clean:
	for d in $(app_list); do \
                make -C $$d clean; \
	done
	rm -f *.order *.symvers

