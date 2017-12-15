#ifndef WF_CHAR_H_
#define WF_CHAR_H_

struct wf_buffer
{
	char *data;
	int size;
	int len;
};

extern void wf_buffer_free(struct wf_buffer *buffer, int free_self);
extern struct wf_buffer *wf_buffer_malloc(struct wf_buffer *buffer, unsigned int size);
extern struct wf_buffer *wf_buffer_remalloc(struct wf_buffer *buffer, unsigned int size);
extern struct wf_buffer *wf_buffer_set(struct wf_buffer *buffer, char *data, int size);
extern struct wf_buffer *wf_buffer_cpy(struct wf_buffer *dst, struct wf_buffer *src);
extern struct wf_buffer *wf_buffer_cat(struct wf_buffer *dst, struct wf_buffer *src);
extern struct wf_buffer *wf_buffer_append(struct wf_buffer *dst, void *src, int size);



// 0 <= max <= 128
extern int time2str_format(long tv, char *out, char *fmt, int max);
// 0 <= max <= 128
extern char *time2str_pformat(long tv, char *out, char *fmt, int max);
extern char *time2str(long tv, char *out);
extern char *timenow2str(char *out);



extern int urlencode(unsigned char *src, unsigned char *dest);

extern int str2mac(char *str, unsigned char *mac);


extern void wipe_off_CRLF_inEnd(char *str);
extern void wipe_off_blank(char *str_in, char *str_out, int out_size);


extern char *str_skip_blank(char *str);
extern char *str_find_blank(char *str);
extern int str_replace(char *str, char *substr, char *repace, char *out);
extern int str_asc_num(char *str, int size);


// only can be used array copy, dst must be array ptr
#ifndef strcpy_array
#define strcpy_array(dst, src)	do{\
	strncpy(dst, src, sizeof(dst)-1);\
	dst[sizeof(dst)-1] = '\0';\
	}while(0)
#endif

// if <string.h> declare strupr, then don't use this function
extern char *strupr_2(char *str);
#ifndef strupr
#define strupr(str)	strupr_2(str)
#endif
// if <string.h> declare strnset, then don't use this function
extern char *strnset_2(char *str, char ch, unsigned n);
#ifndef strnset
#define strnset(str, ch, n)	strnset_2(str, ch, n)
#endif
#define isAlphabet(c)		( (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') )
// if <string.h> declare strnicmp, then don't use this function
extern int strnicmp_2(char *str1, char *str2, int len);
#ifndef strnicmp
#define strnicmp(str1, str2, len)	strnicmp_2(str1, str2, len)
#endif
// if <string.h> declare stricmp, then don't use this function
extern int stricmp_2(char *str1, char *str2);
#ifndef stricmp
#define stricmp(str1, str2)		stricmp_2(str1, str2)
#endif
// if <string.h> declare strcmpi, then don't use this function
#define strcmpi_2(str1, str2)	stricmp_2(str1, str2)
#ifndef strcmpi
#define strcmpi(str1, str2)		stricmp_2(str1, str2)
#endif
// if <string.h> declare strrev, then don't use this function
extern char *strrev_2(char *s);
#ifndef strrev
#define strrev(s)	strrev_2(s)
#endif


// URL type
#define URL_HTTP		1
#define URL_FTP		2
extern int parseURL(char *URL);
extern void intToByte(unsigned int in,unsigned char *out);
extern void byteToInt(unsigned char *in,unsigned int *out);
extern int ascToInt( char *asc_ptr,int *out );
extern int ascToUInt( char *asc_ptr,unsigned int *out );
extern int copyIP(char *str,char *out);
extern int copyNum(char *str,char *out);


typedef unsigned char   BYTE;
extern int uInttobcd( char *ppDestination,unsigned int pLvar,int bcdlen );
extern void bcd_to_asc( BYTE *asc_buf, BYTE *bcd_buf,int n );
#define bcd2asc(asc, bcd, bcd_n)	bcd_to_asc(asc, bcd, bcd_n*2)

extern void asc_to_bcd( BYTE *bcd_buf, BYTE *asc_buf,int n );
#define asc2bcd(bcd, asc, asc_n)	asc_to_bcd(bcd, asc, asc_n)

extern unsigned int bcdtouInt( BYTE *bcd_ptr,int pares );
extern long asctol( BYTE *bcd_ptr,int pares );
extern void ltoasc( char *ppDestination,long pLvar,int INumber );
extern int ltobcd( char *ppDestination,int pLvar,int bcdlen );
extern void l_to_decimal(long sou,char *tar);
extern void a_to_decimal(char *sou,char *tar);
extern void tohex(BYTE *str,BYTE *hexstr);

#endif

