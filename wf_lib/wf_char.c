#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "wf_char.h"

void wf_buffer_free(struct wf_buffer *buffer, int free_self)
{
	if(!buffer)
		return;
	if(buffer->data)
		free(buffer->data);
	
	if(free_self)
		free(buffer);
	else
		memset(buffer, 0, sizeof(struct wf_buffer));
}

struct wf_buffer *wf_buffer_malloc(struct wf_buffer *buffer, unsigned int size)
{
	struct wf_buffer *p = buffer, *p_malloc = NULL;

	if(!size)
		return NULL;
	if(!p){
		p = (struct wf_buffer *)malloc(sizeof(struct wf_buffer));
		if(!p)
			return NULL;
		p_malloc = p;
	}

	p->data = (char *)malloc(size);
	if(!p->data){
		if(p_malloc)
			wf_buffer_free(p, 1);
		return NULL;
	}
	memset(p->data, 0, size);
	p->size = size;
	p->len = 0;
	return p;
}

struct wf_buffer *wf_buffer_remalloc(struct wf_buffer *buffer, unsigned int size)
{
	if(!buffer || !size)
		return NULL;
	if(buffer->data)
		free(buffer->data);
	buffer->data = (char *)malloc(size);
	if(!buffer->data){
		return NULL;
	}
	memset(buffer->data, 0, size);
	buffer->size = size;
	buffer->len = 0;
	return buffer;
}

struct wf_buffer *wf_buffer_set(struct wf_buffer *buffer, char *data, int size)
{
	if(!buffer || !data || !size)
		return NULL;
	if((size+1) > buffer->size)
		wf_buffer_remalloc(buffer, size+1);
	else
		memset(buffer->data, 0, buffer->size);
	memcpy(buffer->data, data, size);
	buffer->len = size;
	buffer->data[buffer->len] = '\0';
	return buffer;
}

struct wf_buffer *wf_buffer_cpy(struct wf_buffer *dst, struct wf_buffer *src)
{
	struct wf_buffer *p = dst;

	if(!src || !src->data || !src->size)
		return NULL;
	if(!p)
		p = (struct wf_buffer *)malloc(sizeof(struct wf_buffer));

	p = wf_buffer_remalloc(p, src->size);
	if(!p)
		return NULL;

	memcpy(p->data, src->data, p->size);
	p->len = src->len;
	return p;
}

struct wf_buffer *wf_buffer_cat(struct wf_buffer *dst, struct wf_buffer *src)
{
	struct wf_buffer new_buffer = {0};
	int new_size = 0;
	if(!dst)
		return NULL;
	if(!src || !src->data || !src->len)
		return dst;
	
	new_size = dst->len + src->len + 1;
	if(new_size > dst->size && !wf_buffer_malloc(&new_buffer, new_size))
		return NULL;
	if(new_buffer.data){
		memcpy(new_buffer.data, dst->data, dst->len);
		if(dst->data)
			free(dst->data);
		dst->data = new_buffer.data;
		dst->size = new_buffer.size;
	}
	memcpy(dst->data + dst->len, src->data, src->len);
	dst->len += src->len;
	dst->data[dst->len] = '\0';
	
	return dst;
}

struct wf_buffer *wf_buffer_append(struct wf_buffer *dst, void *src, int size)
{
	struct wf_buffer tmp;

	tmp->data = src;
	tmp->len = size;
	return wf_buffer_cat(dst, &tmp);
}



char *get_row(char *linestr, int index, char *dst, unsigned int size)
{
	int idx = -1;
	char *str = linestr, *node = NULL, *tmp = NULL;
	unsigned int copy_len = 0;

	if(!linestr || index < 0 || !dst || !size)
		return NULL;
//	printf("get_row linestr: %s \n", linestr);
	while(str)
	{
		node = str_skip_blank(str);
		++idx;
		if(node){
			tmp = str_find_blank(node);
			str = tmp;
		}
		else
			break;
		if(idx == index){
			if(node){
				if(tmp){
					copy_len = tmp - node;
					if(copy_len > size)
						copy_len = size;
				}
				else
					copy_len = size;
				strncpy(dst, node, copy_len);
				dst[copy_len] = '\0';
//				printf("get_row [idx: %d][len: %d]: %s \n", index, copy_len, dst);
			}
			return node;
		}
	}
	return NULL;
}

char *get_row_int(char *linestr, int index, int *dst, char *fmt)
{
	char buf[16] = {0}, *str = NULL;

	str = get_row(linestr, index, buf, sizeof(buf)-1);
	if(str){
		sscanf(buf, fmt, dst);
	}
	return str;
}

static unsigned char url_to_hex(unsigned char code)
{
	static char hex[] = "0123456789abcdef";

	return hex[code & 0x0F];
}

int urlencode( unsigned char *src, unsigned char *dest )
{
#define char_to_hex(x)	(x > 9 ? x + 55: x + 48)
	char ch;
	int  len = 0;

	while (*src)
	{
		ch = (char)*src;
		if (*src == ' ')
		{
			*dest++ = '+';
		}
		else if( (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || 
			(ch >= '0' && ch <= '9') || strchr("-_.!~*'()", ch) )
		{
			*dest++ = *src;
		}
		else
		{
			*dest++ = '%';
		#if 0
			*dest++ = char_to_hex( (unsigned char)(ch >> 4) );
			*dest++ = char_to_hex( (unsigned char)(ch & 0x0F) );
		#else
			*dest++ = url_to_hex( (unsigned char)(ch >> 4) );
			*dest++ = url_to_hex( (unsigned char)(ch & 0x0F) );
		#endif
		} 
		++src;
		++len;
	}
	*dest = 0;
	return len;
}

char *str_skip_blank(char *str)
{
	char *s = str;
	if(s == NULL)
		return NULL;
	while(*s != '\0')
	{
		if( *s == ' ' || *s == '\t' )
			++s;
		else
			return s;
	}
	return NULL;
}

char *str_find_blank(char *str)
{
	char *s = str;
	if(s == NULL)
		return NULL;
	while(*s != '\0')
	{
		if( *s == ' ' || *s == '\t' )
			return s;
		else
			++s;
	}
	return NULL;
}

int str_replace(char *str, char *substr, char *repace, char *out)
{
	char *cur = str, *find = NULL, *pout = out;
	int num = 0, sublen, replen;
	unsigned int len;
	
	if(!substr || !repace)
		goto CPY;
	
	sublen = strlen(substr);
	replen = strlen(repace);
	if(sublen <= 0 || replen <= 0)
		goto CPY;
	
	while(*cur != '\0')
	{
		find = strstr(cur, substr);
		if(find){
			++num;
			len = (unsigned int)(find-cur);
			memcpy(pout, cur, len);
			pout += len;
			memcpy(pout, repace, replen);
			pout += replen;
			*pout = '\0';
			cur = find + sublen;
		}
		else{
			strcpy(pout, cur);
			break;
		}
	}

	return num;

CPY:
	if(str && out){
		strcpy(out, str);
		return 0;
	}
	else
		return -1;
}

int str_asc_num(char *str, int size)
{
	int i=0, n=0;

	for(i=0; i<size; i++)
	{
		if( str[i] >= 1 && str[i] <= 127 )
			++n;
	}

	return n;
}

char *time2str(long tv, char *out)
{
	time_t t = tv;
	char *dst = out;
	struct tm *local_t;
	static char time_str[64]={'\0'};

	local_t=localtime(&t);

	if( !dst )
		dst = time_str;

	sprintf( dst, "%04d-%02d-%02d %02d:%02d:%02d", 
		local_t->tm_year+1900, local_t->tm_mon+1,local_t->tm_mday,
		local_t->tm_hour,local_t->tm_min,local_t->tm_sec);

	return dst;
}

char *timenow2str(char *out)
{
	return time2str(time(NULL), out);
}

static char *time2str_f(time_t tv, char *out, char *fmt, int max, int *n)
{
	time_t t = tv;
	char *dst = out, *pfmt=fmt, *start=NULL;
	struct tm *local_t;
	static char time_str[128+1]={'\0'};
	int len=0, count=0, max_size=max;

	local_t=localtime(&t);

	if( !dst )
		dst = time_str;
	start = dst;
	if(max_size <= 0 || max_size > 128)
		max_size = 128;
		
	if(fmt)
	{
		while(*pfmt != '\0')
		{
			if(*pfmt != '%'){
				*dst++ = *pfmt;
				++count;
			}
			else{
				len = 1;
				++pfmt;
				if( *pfmt == 'Y' )
					len = sprintf(dst, "%04d", local_t->tm_year+1900);
				else if( *pfmt == 'M' )
					len = sprintf(dst, "%02d", local_t->tm_mon+1);
				else if( *pfmt == 'D' )
					len = sprintf(dst, "%02d", local_t->tm_mday);
				else if( *pfmt == 'h' )
					len = sprintf(dst, "%02d", local_t->tm_hour);
				else if( *pfmt == 'm' )
					len = sprintf(dst, "%02d", local_t->tm_min);
				else if( *pfmt == 's' )
					len = sprintf(dst, "%02d", local_t->tm_sec);
				else
					*dst = *--pfmt;
				dst += len;
				count += len;
			}
			
			if(count >= max_size)
				break;
			++pfmt;
		}
		*dst = '\0';
		len = dst - start;
	}
	else
	{
		len = sprintf( dst, "%04d-%02d-%02d %02d:%02d:%02d", 
			local_t->tm_year+1900, local_t->tm_mon+1,local_t->tm_mday,
			local_t->tm_hour,local_t->tm_min,local_t->tm_sec);
	}

	if(n)
		*n = len;
	return start;
}

int time2str_format(long tv, char *out, char *fmt, int max)
{
	int len=0;
	time2str_f(tv, out, fmt, max, &len);

	return len;
}

char *time2str_pformat(long tv, char *out, char *fmt, int max)
{
	return time2str_f(tv, out, fmt, max, NULL);
}

void wipe_off_CRLF_inEnd(char *str)
{
#define CRLF_char(c)	( c == '\r' || c == '\n' )
	int i=0, len=strlen(str);

	for(i=len-1; i>=0; i--)
	{
		if( CRLF_char(str[i]) )
			str[i] = '\0';
		else
			break;
	}
}
void wipe_off_blank(char *str_in, char *str_out, int out_size)
{
#define wipe_char(c)	( c == ' ' || c == '\t' )
	int i=0, j=0, in_len=0;
	
	if(str_in == NULL || str_out == NULL || out_size == 0)
		return;
	in_len = strlen(str_in);
	if(out_size < in_len)
		return;

	for(i=0; i<in_len; i++)
	{
		if( wipe_char(str_in[i]) )
			continue;
		else
			str_out[j++] = str_in[i];
	}
	str_out[j] = '\0';
}

int str2mac(char *str, unsigned char *mac)
{
	unsigned int m[6];
	int i;
	if(strstr((char*)str, ":"))
	{
		sscanf((char*)str, "%02x:%02x:%02x:%02x:%02x:%02x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]);
	}
	else if(strstr((char*)str, "-"))
	{
		sscanf((char*)str, "%02x-%02x-%02x-%02x-%02x-%02x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]);
	}
	else if(strlen(str) == 12)
	{
		sscanf((char*)str, "%02x%02x%02x%02x%02x%02x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]);
	}
	else
		return -1;

	for(i = 0; i < 6; i++)
		mac[i] = (char)m[i];

	return 0;
}



char *strupr_2(char *str)
{
	char *s = str;
	while(*s != '\0')
	{
		if(*s >= 'a' && *s <= 'z')
			*s -= 32;
	}
	return str;
}

char *strnset_2(char *str, char ch, unsigned n)
{
	int i;
	if(strlen(str) < n)
		return NULL;
	for(i=0; i<n; i++)
	{
		str[i] = ch;
	}
	return str;
}
/*
int chicmp(char c1, char c2)
{
	if( isAlphabet(c) )
	{
		if( (c1 + 32) != c2 && (c2 + 32) != c1 )
			return 1;
	}
	else
	{
		if(c1 != c2)
			return 1;
	}

	return 0;
}
*/
int strnicmp_2(char *str1, char *str2, int len)
{
	int i=0, len1=strlen(str1), len2=strlen(str2);

	if(len1 < len2 || len1 < len || len2 < len)
		return 1;

	for(i=0; i<len; i++)
	{
		if( isAlphabet(str2[i]) )
		{
			if( (str1[i] + 32) != str2[i] && (str2[i] + 32) != str1[i] )
				return 1;
		}
		else
		{
			if( str1[i] != str2[i] )
				return 1;
		}
	}

	return 0;
}

int stricmp_2(char *str1, char *str2)
{
	int i, len;

	len = strlen(str1);
	if(len != strlen(str2))
		return 1;
	
	for(i=0; i<len; i++)
	{
		if( isAlphabet(str2[i]) )
		{
			if( (str1[i] + 32) != str2[i] && (str2[i] + 32) != str1[i] )
				return 1;
		}
		else
		{
			if( str1[i] != str2[i] )
				return 1;
		}
	}

	return 0;
}

char *strrev_2(char *s)
{
	int i, j;
	char c;
	for( i = 0, j = strlen(s)-1; i < j; ++i, --j )
	{
		c = s[i];
		s[i] = s[j];
		s[j] = c;
	}
	return s;
}



int parseURL(char *URL)
{
	if(URL == NULL)	return -1;
	if( strncmp(URL,"http://",strlen("http://")) == 0 )	return URL_HTTP;	// http
	else if( strncmp(URL,"ftp://",strlen("ftp://")) == 0 )	return URL_FTP;	// ftp
	else	
		return 0;	// other
}
void intToByte(unsigned int in,unsigned char *out)
{
	int i=0,int_tmp=in;
	unsigned char *p=NULL;
	/*低位在前*/
	p = (unsigned char *)&int_tmp;
	out[i++] = *p++;
	out[i++] = *p++;
	out[i++] = *p++;
	out[i++] = *p++;
}
void byteToInt(unsigned char *in,unsigned int *out)
{
	unsigned int i=0,int_tmp=0;
	unsigned char *p=NULL;
	/*低位在前*/
	p = (unsigned char *)&int_tmp;
	*p++ = in[i++];
	*p++ = in[i++];
	*p++ = in[i++];
	*p++ = in[i++];
	*out = int_tmp;
}
/*ASC码转换为整型
输入:
asc_ptr: ASC 码字符串
输出:
out: 整型数
返回值:
>=0 : 有效ASC 码字符串的长度
<0 : 出错
*/
int ascToInt( char *asc_ptr,int *out )
{
	int len=0,value=0,isMinus=0;
	if( asc_ptr==NULL || out==NULL )	return -1;
	if(*asc_ptr == '-')
	{
			++len;
			isMinus = 1;
			++asc_ptr;
	}
	while(*asc_ptr)
	{
		if (*asc_ptr >= '0' && *asc_ptr <= '9')
		{
			++len;
			value = value * 10 + ( *asc_ptr - '0' );
			++asc_ptr;
		}
		else
			break;
	}
	if(isMinus)	value = value * (-1);
	*out = value;
	
	return len;
}

/*ASC码转换为无符号整型
输入:
asc_ptr: ASC 码字符串
输出:
out: 整型数
返回值:
>=0 : 有效ASC 码字符串的长度
<0 : 出错
*/
int ascToUInt( char *asc_ptr,unsigned int *out )
{
	int len=0;
	unsigned int value=0;
	if( asc_ptr==NULL || out==NULL )	return -1;
	
	while(*asc_ptr)
	{
		if (*asc_ptr >= '0' && *asc_ptr <= '9')
		{
			++len;
			value = value * 10 + ( *asc_ptr - '0' );
			++asc_ptr;
		}
		else
			break;
	}
	*out = value;
	
	return len;
}

/*复制IP 字符串
输入:
str: 字符串
输出:
out: IP 字符串
返回值:
>=0 : 有效IP 字符串的长度
<0 : 出错
*/
int copyIP(char *str,char *out)
{
	int len=0,num=0;
	char *pout = out;
	if(str==NULL || out==NULL)		return -1;

	while(*str)
	{
		if (*str >= '0' && *str <= '9')
		{
			++len;
			*pout = *str;
			++str;++pout;
		}
		else if(*str == '.')
		{
			++num;
			if(num>3)	break;
			++len;
			*pout = *str;
			++str;++pout;
		}
		else
			break;
	}
	if(num < 3)	return -1;
	
	return len;
}
/*复制数字字符串
输入:
str: 字符串
输出:
out: 数字符串
返回值:
>=0 : 有效数字符串的长度
<0 : 出错
*/
int copyNum(char *str,char *out)
{
	int len=0;
	char *pout = out;
	if(str==NULL || out==NULL)	return -1;

	while(*str)
	{
		if (*str >= '0' && *str <= '9')
		{
			++len;
			*pout = *str;
			++str;++pout;
		}
		else
			break;
	}

	return len;
}



int uInttobcd( char *ppDestination,unsigned int pLvar,int bcdlen )
{
	char strTmp1[20];
	char format[20];
	char    ch[8];

	memset(format,'\0',20);
	memset(ch,'\0',8);
	memset(strTmp1,'\0',20);
	memcpy(format,"%0",2);
	sprintf(ch,"%d",bcdlen*2);
	memcpy(&format[2],ch,strlen(ch));
	memcpy(&format[2+strlen(ch)],"d",1);

	sprintf(strTmp1,format,pLvar);

	asc_to_bcd( (BYTE *)ppDestination, (BYTE *)strTmp1, bcdlen * 2 );

	return bcdlen;
}

/*=======================================================================
 
bcd_to_asc() - translate BCD string into ASCII string
 <n> : ascii char number
=======================================================================*/
void abcd_to_asc( unsigned char *abyte )
{
	if ( *abyte<=9 )
		*abyte = *abyte + '0';
	else
		*abyte = *abyte + 'A' - 10;
}

void bcd_to_asc( BYTE *asc_buf, BYTE *bcd_buf,int n )
{
	int i, j;
	j = 0;
	for ( i = 0; i < n / 2; i++) 
	{
		asc_buf[j] = (bcd_buf[i] & 0xf0) >> 4;
		abcd_to_asc( &asc_buf[j] );
		j ++;
		asc_buf[j] = bcd_buf[i] & 0x0f;
		abcd_to_asc( &asc_buf[j] );
		j ++;
	}
	if ( n % 2 ) 
	{
		asc_buf[j] = (bcd_buf[i] & 0xf0) >> 4;
		abcd_to_asc( &asc_buf[j] );
	}
}

/*=======================================================================
 
asc_to_bcd() - Translate ASCII string into BCD string
 <n> : number of ascii character
=======================================================================*/
BYTE aasc_to_bcd( BYTE asc )
{
	BYTE bcd;

	if ( (asc >= '0') && (asc <= '9') )
		bcd = asc - '0';
	else if ( (asc >= 'A') && (asc <= 'F') )
		bcd = asc - 'A' + 10;
	else if ( (asc >= 'a') && (asc <= 'f') )
		bcd = asc - 'a' + 10;
	else if(asc=='=')
		bcd=0x0D;
	else 
	{
		/* printf( "\f[Warning] : Bad HEX digid" ); */
		bcd = 0;
	}

	return bcd;
}

void asc_to_bcd( BYTE *bcd_buf, BYTE *asc_buf,int n )
{
	int i, j;
	j = 0;

	for (i=0 ; i < (n + 1) / 2; i++) 
	{
		bcd_buf[i] = aasc_to_bcd( asc_buf[j++] );
		bcd_buf[i] = ((j>=n) ? 0x00 : aasc_to_bcd( asc_buf[j++] ))
				+ ( bcd_buf[i] << 4 );
	}
}

/*========================================================================
 
bcdtoi (char) - convert a bcd to unsigned int
========================================================================*/

unsigned int bcdtoi (BYTE bcd_value)
{
	return ( ((bcd_value >> 4) & 0x0f) * 10 + (bcd_value & 0x0f) );
}

/*============================================================================
  bcdtol: translate <pares> of <bcd_ptr> chars to unsigned int
============================================================================*/
unsigned int bcdtouInt( BYTE *bcd_ptr,int pares )
{
	unsigned int value = 0;
	if ( pares <= 0 )
		return 0;
	while ( pares-- > 0 )
		value = value * 100 + bcdtoi( *bcd_ptr++);

	return value;
}

/*============================================================================
  asctol: translate <pares> of <asc_ptr> ascii chars to long
============================================================================*/
long asctol( BYTE *asc_ptr,int pares )
{
	long value = 0;
	if ( pares <= 0 )
		return - 1;
	while ( pares-- > 0 )
	{
		if ( *asc_ptr >= '0' && *asc_ptr <= '9' )
			value = value * 10 + ( *asc_ptr++ - '0' );
		else
			return - 1;
	}
	return value;
}

/*============================================================================
  
ltoasc: translate <long> to <num> of <asc_ptr> ascii chars
============================================================================*/
void ltoasc( char *ppDestination,long pLvar,int INumber )
{
	char format[80];
	char    ch[8];

	memset(format,'\0',80);
	memset(format,'\0',8);
	memcpy(format,"%0",2);
	sprintf(ch,"%d",INumber);
	ch[strlen(ch)]='\0';
	memcpy(&format[2],ch,strlen(ch));
	memcpy(&format[2+strlen(ch)],"ld",2);

	sprintf( ppDestination, format, pLvar );
}


/*============================================================================
  ltobcd: translate <long> to <num> of <bcd_ptr> bcd chars
============================================================================*/
int ltobcd( char *ppDestination,int pLvar,int bcdlen )
{
	char strTmp1[20];
	char format[20];
	char ch[8];

	memset(format,'\0',20);
	memset(ch,'\0',8);
	memset(strTmp1,'\0',20);
	memcpy(format,"%0",2);
	sprintf(ch,"%d",bcdlen*2);
	memcpy(&format[2],ch,strlen(ch));
	memcpy(&format[2+strlen(ch)],"d",1);
	sprintf(strTmp1,format,pLvar);

	asc_to_bcd( (BYTE *)ppDestination, (BYTE *)strTmp1, bcdlen * 2 );

	return bcdlen;
}

void l_to_decimal(long sou,char *tar)
{
	char tmp[20];
	int  i,j;

	memset(tmp, '\0', 15);
	sprintf(tmp, "%ld", sou);
	switch (strlen(tmp)) 
	{
		case 1:
			strcpy(tar, "0.0");
			strcat(tar, tmp);
			break;
		case 2:
			strcpy(tar, "0.");
			strcat(tar, tmp);
			break;
		default:
			j = 0;
			for (i=0;i<(int)strlen(tmp);i++) 
			{
				if (i == (int)strlen(tmp)-2) 
				{
					tar[i+j] = '.';
					j++;
				}
				tar[i+j] = tmp[i];
			}
			tar[strlen(tmp)+1] = '\0';
	}
}

void a_to_decimal(char *sou,char *tar)
{
	char tmp[15];
	int  i,j;
	
	memset(tmp, '\0', 15);
	strcpy(tmp, sou);
	switch (strlen(tmp)) 
	{
		case 1:
			strcpy(tar, "0.0");
			strcat(tar, tmp);
			break;
		case 2:
			strcpy(tar, "0.");
			strcat(tar, tmp);
			break;
		default:
			j = 0;
			for (i=0;i<(int)strlen(tmp);i++) 
			{
				if (i == (int)strlen(tmp)-2) 
				{
					tar[i+j] = '.';
					j++;
				}
				tar[i+j] = tmp[i];
			}
			tar[strlen(tmp)+1] = '\0';
	}
}
void tohex(BYTE *str,BYTE *hexstr)
{
	int i;

	for (i=0;i<8;i++) 
	{
		hexstr[2*i] = (str[i] >> 4) & 0x0f;
		if(hexstr[2*i] < 10)
			hexstr[2*i] += '0';
		else
			hexstr[2*i] = hexstr[2*i] - 10 + 'A';
		hexstr[2*i+1] = str[i] & 0x0f;
		if(hexstr[2*i + 1] < 10)
			hexstr[2*i + 1] += '0';
		else
			hexstr[2*i + 1] = hexstr[2*i + 1] - 10 + 'A';
	}
	hexstr[16] = '\0';
}

void ascadd(char* string,char* secondString,int len)
{
	int i=1,j;
	int upflag=0;

	while(i<=len)
	{
		j=len-i;
		string[j]=string[j]+(char)upflag+(secondString[j]-'0');
		if (string[j]>'9')
		{
			upflag = 1;
			string[j]=string[j]-10;
		}
		else
			upflag=0;
		i++;
	}
}
void ascdec(char* string,char* secondString,int len)
{
	int i=1,j;
	int upflag=0;

	while(i<=len)
	{
		j=len-i;
		string[j]=string[j]-(char)upflag-(secondString[j]-'0');
		if (string[j]<'0')
		{
			upflag = 1;
			string[j]=string[j]+10;
		}
		else
			upflag=0;
		i++;
	}
}

#if 0
void main()
{
	char str[100] = "abcdefg";
	printf("%s \n", strrev(str));
}
#endif

