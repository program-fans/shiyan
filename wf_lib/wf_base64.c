#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if 0
#include <sys/stat.h>
#endif
#include "wf_base64.h"

static char base64_table[64] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 
							'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 
							'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};
static unsigned char base64_decode_table[123] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
											0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
											0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
											62, 0, 0, 0, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 
											0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 
											14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 
											0, 0, 0, 0, 0, 0, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 
											37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51};

static inline char base64_look_table(unsigned char in)
{
#if	1
	return base64_table[in];
#else
	if(in >= 0 && in<= 25)
		return (char)(in + 65);		// 65  'A'
	else if(in >= 26 && in<= 51)
		return (char)(in + 71);		// in - 26 + 97   'a'
	else if(in >= 52 && in<= 61)
		return (char)(in - 4);		// in - 52 + 48   '0'
	else if(in == 62)
		return (char)43;			// 43  '+'
	else if(in == 63)
		return (char)47;			// 47   '/'
#endif
}

static inline unsigned char base64_look_decode_table(char in)
{
#if 1
	return base64_decode_table[(int)in];
#else
	if(in >= 'A' && in <= 'Z')
		return (unsigned char)(in - 65);
	else if(in >= 'a' && in <= 'z')
		return (unsigned char)(in - 71);		// in - 97 + 26
	else if(in >= '0' && in <= '9')
		return (unsigned char)(in + 4);		// in - 48 + 52
	else if(in == '+')
		return (unsigned char)62;
	else if(in == '/')
		return (unsigned char)63;
#endif
}

static unsigned int base64_char_decode(char w, char x, char y, char z, unsigned char *out)
{
	unsigned char a, b, c, d;
	unsigned int i = 0;

	a = base64_look_decode_table(w);
	b = base64_look_decode_table(x);

	out[i] = ((a << 2) & 0xFC) | ((b >> 4) & 0x03);
	++i;

	if(y == '=')
		goto END;
	c = base64_look_decode_table(y);
	out[i] = ((b << 4) & 0xF0) | ((c >> 2) & 0x0F);
	++i;
	
	if(z == '=')
		goto END;
	d = base64_look_decode_table(z);
	out[i] = ((c << 6) & 0xC0) | (d & 0x3F);
	++i;

END:
#if 0
	if(i == 1)
		printf("in: %c%c%c%c; out: %02x [%u %u]\n", in[0], in[1], in[2], in[3], out[0], a, b);
	else if(i == 2)
		printf("in: %c%c%c%c; out: %02x %02x [%u %u %u]\n", in[0], in[1], in[2], in[3], out[0], out[1], a, b, c);
	else
		printf("in: %c%c%c%c; out: %02x %02x %02x [%u %u %u %u]\n", in[0], in[1], in[2], in[3], out[0], out[1], out[2], a, b, c, d);
#endif
	return i;
}

unsigned int base64_decode(char *in, unsigned int in_len, unsigned char *out, unsigned int out_size)
{
	unsigned int i, j, n, len=0, tmp_len;
	unsigned char out_tmp[3], *pout=out;
	
	if(!in || !in_len || !out || !out_size)
		return 0;
	n = in_len % 4;
	if(n)
		return 0;
	n = in_len / 4;
	//printf("in_len: %u, /4: %u;  out_size: %u \n", in_len, n, out_size);

	for(i=0, j=0; i<n; i++, j+=4)
	{
		tmp_len = base64_char_decode(in[j], in[j+1], in[j+2], in[j+3], out_tmp);
		if((len + tmp_len) > out_size)
			break;
		memcpy(pout, out_tmp, tmp_len);
		pout += tmp_len;
		len += tmp_len;
	}

	return len;
}

static void base64_char_encode(unsigned char a, unsigned char b, unsigned char c, int num, char *out)
{
	unsigned char base64_char;
	int i = 0;

	if(num <= 0)
		return;

	base64_char = ((a >> 2) & 0x3F);
	out[i] = base64_look_table(base64_char);
	++i;

	base64_char = (((a << 4) & 0x30) | ((b >> 4) & 0x0F));
	out[i] = base64_look_table(base64_char);
	++i;

	if(num == 1)
		out[i] = '=';
	else{
		base64_char = (((b << 2) & 0x3C) | ((c >> 6) & 0x03));
		out[i] = base64_look_table(base64_char);
	}
	++i;

	if(num <= 2)
		out[i] = '=';
	else
		out[i] = base64_look_table(c & 0x3F);
	//printf("num: %d; abc: %02x %02x %02x; out: %02x %02x %02x %02x\n", num, a, b, c, out[0], out[1], out[2], out[3]);
}

unsigned int base64_encode(unsigned char *in, unsigned int in_len, char *out, unsigned int out_size)
{
	unsigned int n = 0, m = 0, i=0, j=0;
	char out_tmp[4];
	unsigned int out_len = 0, out_num = 0;
	char *pout = out;
	unsigned char a, b, c;

	if(!in || !in_len || !out || out_size < 4)
		return 0;
	n = in_len / 3; m = in_len % 3;
	out_len = out_size /4;
	//printf("in_len: %u, /3: %u, %%3: %u;   out_size: %u, /4: %u \n", in_len, n, m, out_size, out_len);

	for(i=0, j=0; i<n; i++, j+=3)
	{
		++out_num;
		if(out_num > out_len)
			break;
		memset(out_tmp, 0, sizeof(out_tmp));
		base64_char_encode(in[j], in[j+1], in[j+2], 3, out_tmp);
		memcpy(pout, out_tmp, 4);
		pout += 4;
	}
	if(m){
		++out_num;
		if(out_num <= out_len){
			if(m == 1){
				a = in[in_len - 1];
				b = 0;
				c = 0;
			}
			else{
				a = in[in_len - 2];
				b = in[in_len - 1];
				c = 0;
			}
			memset(out_tmp, 0, sizeof(out_tmp));
			base64_char_encode(a, b, c, m, out_tmp);
			memcpy(pout, out_tmp, 4);
			pout += 4;
		}
	}
	//*pout = '\0';

	return (out_num * 4);
}


void base64_decode_start(struct base64_context *cxt)
{
	memset(cxt, 0, sizeof(struct base64_context));
}

unsigned int base64_decode_process(struct base64_context *cxt, 
	char *in, unsigned int in_len, unsigned char *out, unsigned int out_size)
{
	char *pin = in;
	unsigned int pin_len = in_len, pout_size = out_size;
	unsigned int out_len = 0, tmp;
	unsigned char *pout = out, out_tmp[3]={0};
	
	if(!cxt || !in || !in_len || !out || !out_size)
		return 0;

	//printf("[cxt num: %d, wxy: %c%c%c] in_len: %u, in: %c%c%c \n", cxt->num, cxt->w, cxt->x, cxt->y, in_len, in[0], in[1], in[2]);
	if(cxt->num){
		if(cxt->num == 1){
			tmp = base64_char_decode(cxt->w, in[0], in[1], in[2], out_tmp);
			pin = in + 3;
			pin_len = in_len - 3;
		}
		else if(cxt->num == 2){
			tmp = base64_char_decode(cxt->w, cxt->x, in[0], in[1], out_tmp);
			pin = in + 2;
			pin_len = in_len - 2;
		}
		else{
			tmp = base64_char_decode(cxt->w, cxt->x, cxt->y, in[0], out_tmp);
			pin = in + 1;
			pin_len = in_len - 1;
		}
		if(tmp > out_size)
			return 0;
		memcpy(out, out_tmp, tmp);
		out_len = tmp;
		pout = out + tmp;
		pout_size = out_size - tmp;
	}

	tmp = (in_len + cxt->num) % 4;
	out_len += base64_decode(pin, pin_len -tmp, pout, pout_size);
	cxt->total_len += out_len;

	cxt->num = tmp;
	if(cxt->num == 1){
		cxt->w = in[in_len - 1];
		cxt->x = '\0';
		cxt->y = '\0';
	}
	else if(cxt->num == 2){
		cxt->w = in[in_len - 2];
		cxt->x = in[in_len - 1];
		cxt->y = '\0';
	}
	else if(cxt->num == 3){
		cxt->w = in[in_len - 3];
		cxt->x = in[in_len - 2];
		cxt->y = in[in_len - 1];
	}
	else{
		cxt->num = 0;
		cxt->w = '\0';
		cxt->x = '\0';
		cxt->y = '\0';
	}

	//printf("out_len: %u \n", out_len);
	return out_len;
}

unsigned int base64_decode_finish(struct base64_context *cxt, unsigned char *out, unsigned int out_size)
{
	unsigned int tmp=0;
	unsigned char out_tmp[3] = {0};
	
	if(!cxt || !out || !out_size)
		return 0;

	//printf("base64_decode_finish  cxt->num: %d \n", cxt->num);
	if(cxt->num){
		if(cxt->num == 1){
			return cxt->total_len;
		}
		else if(cxt->num == 2){
			tmp = base64_char_decode(cxt->w, cxt->x, '=', '=', out_tmp);
		}
		else{
			tmp = base64_char_decode(cxt->w, cxt->x, cxt->y, '=', out_tmp);
		}
		if(tmp > out_size)
			return 0;
		memcpy(out, out_tmp, tmp);
		cxt->total_len += tmp;
	}

	return cxt->total_len;
}


void base64_encode_start(struct base64_context *cxt)
{
	memset(cxt, 0, sizeof(struct base64_context));
}

unsigned int base64_encode_process(struct base64_context *cxt, 
	unsigned char *in, unsigned int in_len, char *out, unsigned int out_size)
{
	unsigned char a, b, c;
	char *pout = out;
	unsigned int pout_size = out_size, pin_len = in_len;
	unsigned char *pin = in;
	unsigned int out_len = 0, tmp;
	
	if(!cxt || !in || !in_len || !out || out_size < 4)
		return 0;

	//printf("[cxt num: %d ab: %02x %02x] in_len: %u; in: %02x %02x \n", cxt->num, cxt->a, cxt->b, in_len, in[0], in[1]);
	if(cxt->num){
		if(cxt->num == 1 && in_len == 1){
			base64_char_encode(cxt->a, in[0], 0, 2, out);
			cxt->total_len += 4;
			cxt->a = 0; cxt->b = 0; cxt->num = 0;
			//printf("out_len: 4 \n");
			return 4;
		}

		out_len = 4;
		if(cxt->num == 1){
			base64_char_encode(cxt->a, in[0], in[1], 3, out);
			pin = in + 2;
			pin_len = in_len - 2;
		}
		else{
			base64_char_encode(cxt->a, cxt->b, in[0], 3, out);
			pin = in + 1;
			pin_len = in_len - 1;
		}
		pout = out + 4;
		pout_size = out_size - 4;
	}

	tmp = (in_len + cxt->num) % 3;
	out_len += base64_encode(pin, pin_len - tmp, pout, pout_size);
	cxt->total_len += out_len;

	cxt->num = tmp;
	if(tmp == 1 ){
		cxt->a = in[in_len - 1];
		cxt->b = 0;
	}
	else if(tmp == 2){
		cxt->a = in[in_len - 2];
		cxt->b = in[in_len - 1];
	}
	else{
		cxt->a = 0; cxt->b = 0; cxt->num = 0;
	}

	//printf("out_len: %u \n", out_len);
	return out_len;
}

unsigned int base64_encode_finish(struct base64_context *cxt, char *out, unsigned int out_size)
{
	unsigned char a, b, c;
	
	if(!cxt || !out || out_size < 4)
		return 0;

	if(cxt->num){
		if(cxt->num == 1){
			base64_char_encode(cxt->a, 0, 0, 1, out);
		}
		else if(cxt->num == 2){
			base64_char_encode(cxt->a, cxt->b, 0, 2, out);
		}
		
		cxt->total_len += 4;
		cxt->a = 0; cxt->b = 0; cxt->num = 0;
		return cxt->total_len;
	}

	return cxt->total_len;
}

#if 0
unsigned char chunk[8192] = {0};
char buffer[8192] = {'\0'};

int base64_encode_file(char *file, char *out, unsigned int out_size)
{
	struct base64_context cxt;
	FILE *fp;
	size_t read_len;
	unsigned char in[1024];
	
	if(!file || !out || !out_size)
		return -1;
	fp = fopen(file, "rb");
	if(!fp)
		return -2;

	base64_encode_start(&cxt);
	while(!feof(fp))
	{
		memset(in, 0, sizeof(in));
		read_len = fread(in, 1, sizeof(in), fp);
		if(read_len > 0)
			base64_encode_process(&cxt, in, (unsigned int)read_len, out + cxt.total_len, out_size - cxt.total_len);
	}
	base64_encode_finish(&cxt, out + cxt.total_len, cxt.total_len - out_size);
	fclose(fp);

	return (int)cxt.total_len;
}

int base64_decode_file(char *file, unsigned char *out, unsigned int out_size)
{
	struct base64_context cxt;
	FILE *fp;
	size_t read_len;
	unsigned char in[1026];
	
	if(!file || !out || !out_size)
		return -1;
	fp = fopen(file, "rb");
	if(!fp)
		return -2;

	base64_decode_start(&cxt);
	while(!feof(fp))
	{
		memset(in, 0, sizeof(in));
		read_len = fread(in, 1, sizeof(in), fp);
		if(read_len > 0)
			base64_decode_process(&cxt, (char *)in, (unsigned int)read_len, out + cxt.total_len, out_size - cxt.total_len);
	}
	base64_decode_finish(&cxt, out + cxt.total_len, cxt.total_len - out_size);
	fclose(fp);

	return (int)cxt.total_len;
}

int write_to_file(char *in, char *file)
{
	FILE *fp = fopen(file, "w");
	if(!fp)
		return -1;
	fprintf(fp, "%s", in);
	fclose(fp);
	return 0;
}

int write_chunk_to_file(unsigned char *in, unsigned int len, char *file)
{
	unsigned int w_len;
	FILE *fp = fopen(file, "w");
	if(!fp)
		return -1;
	w_len = (unsigned int)fwrite(in, 1, len, fp);
	fclose(fp);
	return (w_len == len) ? 0 : -2;
}

int main(int argc, char **argv)
{
	int ret=0;
	char out[1024] = {'\0'};
	unsigned char decode[1024] = {0};

#if	1		// for gdb
	char str_1[1024] = "g5wy5vb wry6'l-45 w/[g]-xf90h";
	char str_2[1024] = "/mnt/hgfs/share/tmp/base.PNG";
	char str_3[1024] = "/mnt/hgfs/share/tmp/base_out.PNG";
	argv[1] = str_1;
	argv[2] = str_2;
	argv[3] = str_3;
#endif

	if(!argv[1])
		return 1;
	base64_encode(argv[1], strlen(argv[1]), out, sizeof(out));
	printf("[encode]\n%s\n", out);

	base64_decode(out, strlen(out), decode, sizeof(decode));
	printf("[decode]\n%s\n", (char *)decode);

	if(strcmp(argv[1], (char *)decode) == 0)
		printf("test OK\n");
	else
		printf("test failed\n");

	if(!argv[2])
		return 1;
	printf("[file]: %s\n", argv[2]);
	ret = base64_encode_file(argv[2], buffer, sizeof(buffer));
	printf("[encode %d]\n%s\n", ret, ret>0 ? buffer : " ");

	if(!argv[3])
		return 1;
	printf("[file]: %s\n", argv[3]);
	ret = write_to_file(buffer, argv[3]);
	if(ret < 0){
		printf("write to file error\n");
		return 1;
	}
	ret = base64_decode_file(argv[3], chunk, sizeof(chunk));
	printf("[decode  %d]\n", ret);
	if(ret > 0)
		ret = write_chunk_to_file(chunk, (unsigned int)ret, argv[3]);
	if(ret < 0){
		printf("write to file error\n");
		return 1;
	}
}
#endif

