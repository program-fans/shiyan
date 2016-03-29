#ifndef WF_BASE64_H_
#define WF_BASE64_H_

extern unsigned int base64_encode(unsigned char *in, unsigned int in_len, char *out, unsigned int out_size);

extern unsigned int base64_decode(char *in, unsigned int in_len, unsigned char *out, unsigned int out_size);

struct base64_context
{
	unsigned char a, b;
	char w, x, y;
	int num;
	unsigned int total_len;
};

extern void base64_encode_start(struct base64_context *cxt);

extern unsigned int base64_encode_process(struct base64_context *cxt, 
	unsigned char *in, unsigned int in_len, char *out, unsigned int out_size);

extern unsigned int base64_encode_finish(struct base64_context *cxt, char *out, unsigned int out_size);


extern void base64_decode_start(struct base64_context *cxt);

extern unsigned int base64_decode_process(struct base64_context *cxt, 
	char *in, unsigned int in_len, unsigned char *out, unsigned int out_size);

extern unsigned int base64_decode_finish(struct base64_context *cxt, unsigned char *out, unsigned int out_size);

#endif

