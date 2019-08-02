#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <ctype.h>

#include "random.h"

int get_dev_urandom(void *data, int dlen)
{
	int fret;
	char *dev = "/dev/urandom";
	FILE *fp = NULL;

	if (!data || dlen <= 0)
		return -1;
	
	fp = fopen(dev, "r");
	if (!fp)
		return -2;
	fret = fread(data, 1, dlen, fp);
	fclose(fp);
	return fret;
}

int get_random_num(int max)
{	
	int uret;
	unsigned int urand;
	
	if (max <= 1)
		return 0;
	
	uret = get_dev_urandom(&urand, sizeof(urand));
	if (uret != sizeof(urand)) {
		struct timeval cur_tmval;
		gettimeofday (&cur_tmval, NULL);
		srandom((unsigned int)cur_tmval.tv_usec);
		urand = (unsigned int)random();
	}
	return (int)(urand%max);
}

#include "openssl/md5.h"

static int __get_random_key(void *key, int key_len)
{
	int i;
	int inr = 0;
	char *ptr;
	FILE *fp = NULL;
	pid_t pid_curr;
	struct timeval tmval;
	struct sysinfo sinfo;
	char dev_random[64];
	char line[1024];
	char ibuf[1024];
	MD5_CTX ctx;
	unsigned char md5[16] = {0};

	get_dev_urandom(dev_random, sizeof(dev_random));
	sysinfo(&sinfo);
	gettimeofday(&tmval, NULL);
	pid_curr = getpid();

	fp = fopen("/proc/interrupts", "r");
	if (!fp) {
		printf("open /proc/interrupts error.\n");
	}
	else {
		for (i = 0; i < 100; i++) {
			memset(line, 0, sizeof(line));
			ptr = fgets(line, sizeof(line)-1, fp);
			if (!ptr)
				break;
			// copy digit number
			while (*ptr && inr < sizeof(ibuf)-1) {
				if (isdigit(*ptr))
					ibuf[inr++] = *ptr;
				ptr++;
			}
			if (inr >= sizeof(ibuf)-1)
				break;
		}
		fclose(fp);
	}
	
	MD5_Init(&ctx);
	MD5_Update(&ctx, dev_random, sizeof(dev_random));
	MD5_Update(&ctx, &sinfo, sizeof(sinfo));
	MD5_Update(&ctx, &tmval, sizeof(tmval));
	MD5_Update(&ctx, &pid_curr, sizeof(pid_curr));
	MD5_Update(&ctx, ibuf, inr);
	MD5_Final(md5, &ctx);
	
	memcpy(key, md5, key_len>sizeof(md5)?sizeof(md5):key_len);
	
	return 0;
}

int get_random_key_bin(void *key, int key_len)
{
	int cplen;
	int offset;
	char md5[16];

	if (!key || key_len <= 0)
		return -1;
	
	offset = 0;
	cplen = key_len;	
	while (cplen > 0) {
		memset(md5, 0, sizeof(md5));
		__get_random_key(md5, sizeof(md5));
		memcpy(key+offset, md5, cplen>sizeof(md5)?sizeof(md5):cplen);
		offset += sizeof(md5);
		cplen -= sizeof(md5);
	}
	return 0;
}

int get_random_key_str(char *key, int key_len)
{
	int i;
	const char base64char[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	#define BASE_LEN (sizeof(base64char)-1)
	
	if (!key || key_len <= 0)
		return -1;
	
	get_random_key_bin(key, key_len-1);
	for (i = 0; i < key_len-1; i++) {
		key[i] = base64char[(unsigned char)key[i] % BASE_LEN];
	}
	key[key_len-1] = 0;
	
	return 0;
}

