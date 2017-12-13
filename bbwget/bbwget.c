/* vi: set sw=4 ts=4: */
/*
 * wget - retrieve a file using HTTP or FTP
 *
 * Chip Rosenthal Covad Communications <chip@laserlink.net>
 *
 */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ioctl.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>
#include <fcntl.h>

#include <getopt.h>
#include <setjmp.h>

#include "libbb.h"
#include "wf_misc.h"

// =================== config
#define CONFIG_FEATURE_WGET_STATUSBAR 1
// =================== config -- end


const char *bb_applet_name = "bbwget";

// ==================== from libbb
void bb_show_usage()
{
#define wget_trivial_usage \
	"[-c|--continue] [-q|--quiet] [-O|--output-document file]\n" \
	"\t[--header 'header: value'] [-Y|--proxy on/off]  [-P DIR] [-i ifname] [-a] [-s]"
#define wget_full_usage \
	" retrieves files via HTTP or FTP\n\n" \
	"Options:\n" \
	"\t-c\tcontinue retrieval of aborted transfers\n" \
	"\t-q\tquiet mode - do not print\n" \
	"\t-P\tSet directory prefix to DIR\n" \
	"\t-O\tsave to filename ('-' for stdout)\n" \
	"\t-Y\tuse proxy ('on' or 'off')\n"\
	"\t-a\treturn download progress to someone\n"\
	"\t-i\tbind ifname to download\n"\
	"\t-s\tjust return the file size, do not download"

	fprintf (stderr, "\nUsage: %s%s\n %s%s\n\n", bb_applet_name, wget_trivial_usage,
			   bb_applet_name, wget_full_usage);

	exit(bb_default_error_retval);
}

#define EMULATE_BASENAME	1

char *bb_get_last_path_component(char *path)
{
#if EMULATE_BASENAME
	static const char null_or_empty[] = ".";
#endif
	char *first = path;
	char *last;

#if EMULATE_BASENAME
	if (!path || !*path) {
		return (char *) null_or_empty;
	}
#endif

	last = path - 1;

	while (*path) {
		if ((*path != '/') && (path > ++last)) {
			last = first = path;
		}
		++path;
	}

	if (*first == '/') {
		last = first;
	}
	last[1] = 0;

	return first;
}

char * last_char_is(const char *s, int c)
{
	char *sret = (char *)s;
	if (sret) {
		sret = strrchr(sret, c);
		if(sret != NULL && *(sret+1) != 0)
			sret = NULL;
	}
	return sret;
}

void chomp(char *s)
{
	char *lc = last_char_is(s, '\n');

	if(lc)
		*lc = 0;
}

char *concat_path_file(const char *path, const char *filename)
{
	char *lc;

	if (!path)
		path = "";
	lc = last_char_is(path, '/');
	while (*filename == '/')
		filename++;
	return bb_xasprintf("%s%s%s", path, (lc==NULL ? "/" : ""), filename);
}

#include <termios.h>
//#include <sys/ioctl.h>

/* It is perfectly ok to pass in a NULL for either width or for
 * height, in which case that value will not be set.  */
int get_terminal_width_height(int fd, int *width, int *height)
{
	struct winsize win = { 0, 0, 0, 0 };
	int ret = ioctl(fd, TIOCGWINSZ, &win);
	if (win.ws_row <= 1) win.ws_row = 24;
	if (win.ws_col <= 1) win.ws_col = 80;
	if (height) *height = (int) win.ws_row;
	if (width) *width = (int) win.ws_col;

	return ret;
}

// ==================== from libbb -- end

struct wg_host_info {
	char *host;
	int port;
	char *path;
	int is_ftp;
	char *user;
};

static void parse_url(char *url, struct wg_host_info *h);
static FILE *open_socket(struct sockaddr_in *s_in, char *ifname);
static char *gethdr(char *buf, size_t bufsiz, FILE *fp, int *istrunc);
static int ftpcmd(char *s1, char *s2, FILE *fp, char *buf);


#ifdef LIB_BBWGET
#undef CONFIG_FEATURE_WGET_STATUSBAR
#include "bb_wget_lib.h"
typedef struct bbwget_s{
	long long int filesize;
	int chunked;

#ifdef LIB_BBWGET_FOR_THREAD
	int thread_argc;
	char **thread_argv;
	int exited;
#endif
	bb_wget_lib_t *lib_set;
	void *extend_data;
}bbwget_t;

#define wget_filesize(pwget) (pwget->filesize)
#define wget_chunked(pwget) (pwget->chunked)

#else
#define wget_filesize(pwget) filesize
#define wget_chunked(pwget) chunked

/* Globals (can be accessed from signal handlers */
static long long int filesize = 0;		/* content-length of the file */
static int chunked = 0;			/* chunked transfer encoding */
#ifdef CONFIG_FEATURE_WGET_STATUSBAR
static void progressmeter(int flag);
static char *curfile;			/* Name of current file being transferred. */
static struct timeval start;	/* Time a transfer started. */
/* For progressmeter() -- number of seconds before xfer considered "stalled" */
static const int STALLTIME = 5;
static volatile unsigned long statbytes = 0; /* Number of bytes transferred so far. */
#endif
#endif


static void close_and_delete_outfile(FILE* output, char *fname_out, int do_continue)
{
	char pwd[512]={0};
	
	if (output != stdout && do_continue==0) {
		if(output)
			fclose(output);
		if(!fname_out)
			return;
		
		if(fname_out[0]!='/'){
			getcwd(pwd, sizeof(pwd));	
			if(pwd[strlen(pwd)-1]!='/')
				strcat(pwd, "/");
			if(strlen(pwd) + strlen(fname_out) < sizeof(pwd)){
				strcat(pwd, fname_out);
			}
		}else{
			strncpy(pwd, fname_out, sizeof(pwd)-1);
		}
		
		if(strcmp(pwd, "/dev/null"))
			unlink(fname_out);
	}
}

/* Read NMEMB elements of SIZE bytes into PTR from STREAM.  Returns the
 * number of elements read, and a short count if an eof or non-interrupt
 * error is encountered.  */
static size_t safe_fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
	size_t ret = 0;

	do {
		clearerr(stream);
		ret += fread((char *)ptr + (ret * size), size, nmemb - ret, stream);
	} while (ret < nmemb && ferror(stream) && errno == EINTR);

	return ret;
}

/* Write NMEMB elements of SIZE bytes from PTR to STREAM.  Returns the
 * number of elements written, and a short count if an eof or non-interrupt
 * error is encountered.  */
static size_t safe_fwrite(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
	size_t ret = 0;

	do {
		clearerr(stream);
		ret += fwrite((char *)ptr + (ret * size), size, nmemb - ret, stream);
	} while (ret < nmemb && ferror(stream) && errno == EINTR);

	return ret;
}

/* Read a line or SIZE - 1 bytes into S, whichever is less, from STREAM.
 * Returns S, or NULL if an eof or non-interrupt error is encountered.  */
static char *safe_fgets(char *s, int size, FILE *stream)
{
	char *ret;

	do {
		clearerr(stream);
		ret = fgets(s, size, stream);
	} while (ret == NULL && ferror(stream) && errno == EINTR);

	return ret;
}

#define close_delete_and_die(s...) { \
	close_and_delete_outfile(output, fname_out, do_continue); \
	bb_error_msg_and_die(s); }


#ifdef CONFIG_FEATURE_WGET_AUTHENTICATION
/*
 *  Base64-encode character string
 *  oops... isn't something similar in uuencode.c?
 *  XXX: It would be better to use already existing code
 */
static char *base64enc(unsigned char *p, char *buf, int len) {

	char al[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
		    "0123456789+/";
		char *s = buf;

	while(*p) {
				if (s >= buf+len-4)
					bb_error_msg_and_die("buffer overflow");
		*(s++) = al[(*p >> 2) & 0x3F];
		*(s++) = al[((*p << 4) & 0x30) | ((*(p+1) >> 4) & 0x0F)];
		*s = *(s+1) = '=';
		*(s+2) = 0;
		if (! *(++p)) break;
		*(s++) = al[((*p << 2) & 0x3C) | ((*(p+1) >> 6) & 0x03)];
		if (! *(++p)) break;
		*(s++) = al[*(p++) & 0x3F];
	}

	return buf;
}
#endif

#define WGET_OPT_CONTINUE	1
#define WGET_OPT_QUIET	2
#define WGET_OPT_PASSIVE	4
#define WGET_OPT_OUTNAME	8
#define WGET_OPT_HEADER	16
#define WGET_OPT_PREFIX	32
#define WGET_OPT_PROXY	64
#define WGET_OPT_IFNAME 128
#define WGET_OPT_GET_SIZE 256
#ifdef SIOCSDROPDATA
#define WGET_OPT_DROP_DATA 512
#endif

#ifndef LIB_BBWGET_FOR_THREAD
static const struct option wget_long_options[] = {
	{ "continue",        0, NULL, 'c' },
	{ "quiet",           0, NULL, 'q' },
	{ "passive-ftp",     0, NULL, 139 },
	{ "output-document", 1, NULL, 'O' },
	{ "header",	         1, NULL, 131 },
	{ "directory-prefix",1, NULL, 'P' },
	{ "proxy",           1, NULL, 'Y' },
	{ "ifname",          1, NULL, 'i' },
	{ "get_size",        0, NULL, 's' },
#ifdef SIOCSDROPDATA
	{ "drop_data",        0, NULL, 'd' },
#endif
	{ 0,                 0, 0, 0 }
};
#endif

#ifdef SIOCSDROPDATA
static int set_sk_drop_data(FILE *fp)
{
    int fd = fileno(fp);
	struct ifreq ifr;
    
    if (fd < 0 )
        return -1;

    memset(&ifr, 0, sizeof(ifr));
    if (ioctl(fd, SIOCSDROPDATA, &ifr) < 0) {
        bb_error_msg_and_die("set sk drop data failed");
        return -2;
    }

    return 0;
}
#endif

#ifdef LIB_BBWGET_FOR_THREAD

static void bb_lookup_host_for_thread(struct sockaddr_in *s_in, const char *host)
{
	static pthread_mutex_t	lookup_host_mutex;
	static int lookup_host_init = 0;
	
	if(!lookup_host_init){
		pthread_mutex_init(&lookup_host_mutex, NULL);
		lookup_host_init = 1;
	}
	pthread_mutex_lock(&lookup_host_mutex);
	bb_lookup_host(s_in, host);
	pthread_mutex_unlock(&lookup_host_mutex);
}
#else
static sigjmp_buf wget_jmpbuf;
static void sig_alarm(int signo)
{
	siglongjmp(wget_jmpbuf, 1);
}
#endif

int wget_main(
#ifdef LIB_BBWGET
	bbwget_t *pwget, 
#endif
	int argc, char **argv)
{
	int n, try=5, status;
	unsigned long opt = 0;
	int port;
	char *proxy = 0;
	char *dir_prefix=NULL;
	char *s, buf[512];
	struct stat sbuf;
	char extra_headers[1024];
	char *extra_headers_ptr = extra_headers;
	int extra_headers_left = sizeof(extra_headers);
	struct wg_host_info server, target;
	struct sockaddr_in s_in;
	llist_t *headers_llist = NULL;

	FILE *sfp = NULL;		/* socket to web/ftp server	    */
	FILE *dfp = NULL;		/* socket to ftp server (data)	    */
	char *fname_out = NULL;		/* where to direct output (-O)	    */
	int do_continue = 0;		/* continue a prev transfer (-c)    */
	long beg_range = 0L;		/*   range at which continue begins */
	int got_clen = 0;		/* got content-length: from server  */
	FILE *output;			/* socket to web server		    */
	int quiet_flag = FALSE;		/* Be verry, verry quiet...	    */
	int use_proxy = 1;		/* Use proxies if env vars are set  */
	char *proxy_flag = "on";	/* Use proxies if env vars are set  */
	char *ifname = NULL;
	char just_get_file_size = 0;
#ifdef SIOCSDROPDATA
	char drop_data = 0;
#endif

#ifdef LIB_BBWGET
	bb_wget_lib_t *p_lib_set = pwget->lib_set;
#endif

#ifdef LIB_BBWGET_FOR_THREAD
	struct arg_parse_t bbwget_arglist[] = {
		{"--continue", &do_continue, 0, 0, NULL, ARG_VALUE_TYPE_INT, 1, NULL},
		{"-c", &do_continue, 0, 0, NULL, ARG_VALUE_TYPE_INT, 1, NULL},
		{"--quiet", &quiet_flag, 0, 0, NULL, ARG_VALUE_TYPE_INT, 1, NULL},
		{"-q", &quiet_flag, 0, 0, NULL, ARG_VALUE_TYPE_INT, 1, NULL},
		{"--output-document", &fname_out, 0, 1, arg_deal_default, 0, 0, NULL},
		{"-O", &fname_out, 0, 1, arg_deal_default, 0, 0, NULL},
		{"--directory-prefix", &dir_prefix, 0, 1, arg_deal_default, 0, 0, NULL},
		{"-P", &dir_prefix, 0, 1, arg_deal_default, 0, 0, NULL},
		{"--proxy", &proxy_flag, 0, 1, arg_deal_default, 0, 0, NULL},
		{"-Y", &proxy_flag, 0, 1, arg_deal_default, 0, 0, NULL},
		{"--ifname", &ifname, 0, 1, arg_deal_default, 0, 0, NULL},
		{"-i", &ifname, 0, 1, arg_deal_default, 0, 0, NULL},
		{"--get_size", &just_get_file_size, 0, 0, NULL, ARG_VALUE_TYPE_CHAR, 1, NULL},
		{"-s", &just_get_file_size, 0, 0, NULL, ARG_VALUE_TYPE_CHAR, 1, NULL},
	#ifdef SIOCSDROPDATA
		{"--drop_data", &drop_data, 0, 0, NULL, ARG_VALUE_TYPE_CHAR, 1, NULL},
		{"-d", &drop_data, 0, 0, NULL, ARG_VALUE_TYPE_CHAR, 1, NULL},
	#endif
		arg_parse_t_init_null
	};
	int new_argc = 0;
	char **new_argv = (char **)malloc(sizeof(char *) * argc);

	if(!new_argv)
		return 1;
	memset(new_argv, 0, sizeof(char *) * argc);
	arg_parse(argc, argv, bbwget_arglist, &new_argc, new_argv);
#else
	/*
	 * Crack command line.
	 */
	bb_opt_complementally = "-1:\203::";
	bb_applet_long_options = wget_long_options;
	opt = bb_getopt_ulflags(argc, argv, "cq\213O:\203:P:Y:ai:sd",
					&fname_out, &headers_llist,
					&dir_prefix, &proxy_flag, &ifname);
	if (opt & WGET_OPT_CONTINUE) {
		++do_continue;
	}
	if (opt & WGET_OPT_QUIET) {
		quiet_flag = TRUE;
	}
    if (opt & WGET_OPT_GET_SIZE) {
        just_get_file_size = TRUE;
		printf("get_size\n");
    }
#ifdef SIOCSDROPDATA
    if (opt & WGET_OPT_DROP_DATA) {
        drop_data = TRUE;
    }
#endif

#endif
	if (strcmp(proxy_flag, "off") == 0) {
		/* Use the proxy if necessary. */
		use_proxy = 0;
	}
	if (opt & WGET_OPT_HEADER) {
		while (headers_llist) {
			int arglen = strlen(headers_llist->data);
			if (extra_headers_left - arglen - 2 <= 0)
				bb_error_msg_and_die("extra_headers buffer too small(need %i)", extra_headers_left - arglen);
			strcpy(extra_headers_ptr, headers_llist->data);
			extra_headers_ptr += arglen;
			extra_headers_left -= ( arglen + 2 );
			*extra_headers_ptr++ = '\r';
			*extra_headers_ptr++ = '\n';
			*(extra_headers_ptr + 1) = 0;
			headers_llist = headers_llist->link;
		}
	}
#ifdef LIB_BBWGET_FOR_THREAD
	if(new_argc > 1){
		//printf("[%s] \n", new_argv[1]);
		parse_url(new_argv[1], &target);
	}
	free(new_argv);
#else
	parse_url(argv[optind], &target);
#endif
	server.host = target.host;
	server.port = target.port;

	/*
	 * Use the proxy if necessary.
	 */
	if (use_proxy) {
		proxy = getenv(target.is_ftp ? "ftp_proxy" : "http_proxy");
		if (proxy && *proxy) {
			parse_url(bb_xstrdup(proxy), &server);
		} else {
			use_proxy = 0;
		}
	}

	/* Guess an output filename */
	if (!fname_out) {
		// Dirty hack. Needed because bb_get_last_path_component
		// will destroy trailing / by storing '\0' in last byte!
		if(*target.path && target.path[strlen(target.path)-1]!='/') {
			fname_out =
#ifdef CONFIG_FEATURE_WGET_STATUSBAR
				curfile =
#endif
				bb_get_last_path_component(target.path);
		}
		if (fname_out==NULL || strlen(fname_out)<1) {
			fname_out =
#ifdef CONFIG_FEATURE_WGET_STATUSBAR
				curfile =
#endif
				"index.html";
		}
		if (dir_prefix != NULL)
			fname_out = concat_path_file(dir_prefix, fname_out);
#ifdef CONFIG_FEATURE_WGET_STATUSBAR
	} else {
		curfile = bb_get_last_path_component(fname_out);
#endif
	}

	if (do_continue && !fname_out 
	#ifdef LIB_BBWGET
		&& (!p_lib_set || !p_lib_set->no_output_file)
	#endif
		){
		bb_error_msg_and_die("cannot specify continue (-c) without a filename (-O)");
	}

#ifdef LIB_BBWGET
	if(!p_lib_set || !p_lib_set->no_output_file)
#endif
	{
		/*
		 * Open the output file stream.
		 */
		if (strcmp(fname_out, "-") == 0) {
			output = stdout;
			quiet_flag = TRUE;
		} else {
	        output = bb_xfopen(fname_out, (do_continue ? "a" : "w"));
		}
	}

	/*
	 * Determine where to start transfer.
	 */
	if (do_continue) {
	#ifdef LIB_BBWGET
		if(p_lib_set && p_lib_set->set_beg_range_bytes > 0)
			beg_range = p_lib_set->set_beg_range_bytes;
		else if(!p_lib_set->no_output_file){
	#endif
			if (fstat(fileno(output), &sbuf) < 0)
				bb_perror_msg_and_die("fstat()");
			if (sbuf.st_size > 0)
				beg_range = sbuf.st_size;
			else
				do_continue = 0;
	#ifdef LIB_BBWGET
		}
		else
			do_continue = 0;
	#endif
	}

#ifndef LIB_BBWGET_FOR_THREAD
#ifdef LIB_BBWGET
	if(p_lib_set && p_lib_set->use_sigsetjmp)
#endif
	{
	    /* set the clock to quit, prevent always wait lookup host done */
	    signal(SIGALRM, sig_alarm);
	    if (sigsetjmp(wget_jmpbuf, 1))
	        bb_perror_msg_and_die("lookup host timeout");
	    alarm(10);
	}

	/* We want to do exactly _one_ DNS lookup, since some
	 * sites (i.e. ftp.us.debian.org) use round-robin DNS
	 * and we want to connect to only one IP... */
	bb_lookup_host(&s_in, server.host);
#else
	bb_lookup_host_for_thread(&s_in, server.host);
#endif

#ifndef LIB_BBWGET_FOR_THREAD
#ifdef LIB_BBWGET
	if(p_lib_set && p_lib_set->use_sigsetjmp)
#endif
		alarm(0);
#endif

	s_in.sin_port = server.port;
	if (quiet_flag==FALSE) {
		fprintf(stdout, "Connecting to %s[%s]:%d\n",
				server.host, inet_ntoa(s_in.sin_addr), ntohs(server.port));
	}
#ifdef LIB_BBWGET_FOR_THREAD
	quiet_flag = TRUE;
#endif

	if (use_proxy || !target.is_ftp) {
		/*
		 *  HTTP session
		 */
		do {
			got_clen = wget_chunked(pwget) = 0;

			if (! --try)
				close_delete_and_die("too many redirections");

			/*
			 * Open socket to http server
			 */
			if (sfp) fclose(sfp);
			sfp = open_socket(&s_in, ifname);
		#ifdef SIOCSDROPDATA
            if (drop_data == TRUE)
                set_sk_drop_data(sfp);
		#endif
			/*
			 * Send HTTP request.
			 */
			if (use_proxy) {
				const char *format = "GET %stp://%s:%d/%s HTTP/1.1\r\n";
#ifdef CONFIG_FEATURE_WGET_IP6_LITERAL
				if (strchr (target.host, ':'))
					format = "GET %stp://[%s]:%d/%s HTTP/1.1\r\n";
#endif
				fprintf(sfp, format,
					target.is_ftp ? "f" : "ht", target.host,
					ntohs(target.port), target.path);
			} else {
				fprintf(sfp, "GET /%s HTTP/1.1\r\n", target.path);
			}

			fprintf(sfp, "Host: %s\r\nUser-Agent: Wget\r\n", target.host);

#ifdef CONFIG_FEATURE_WGET_AUTHENTICATION
			if (target.user) {
				fprintf(sfp, "Authorization: Basic %s\r\n",
					base64enc((unsigned char*)target.user, buf, sizeof(buf)));
			}
			if (use_proxy && server.user) {
				fprintf(sfp, "Proxy-Authorization: Basic %s\r\n",
					base64enc((unsigned char*)server.user, buf, sizeof(buf)));
			}
#endif

			if (do_continue)
				fprintf(sfp, "Range: bytes=%ld-\r\n", beg_range);
			if(extra_headers_left < sizeof(extra_headers))
				fputs(extra_headers,sfp);
			fprintf(sfp,"Connection: close\r\n\r\n");

			/*
			* Retrieve HTTP response line and check for "200" status code.
			*/
read_response:

            /* will not receive any data, just wait socket error and return 
             *      when set the flag: drop_data.  */
            if (fgets(buf, sizeof(buf), sfp) == NULL)
                close_delete_and_die("no response from server");

			for (s = buf ; *s != '\0' && !isspace(*s) ; ++s)
			;
			for ( ; isspace(*s) ; ++s)
			;
			switch (status = atoi(s)) {
				case 0:
				case 100:
					while (gethdr(buf, sizeof(buf), sfp, &n) != NULL);
					goto read_response;
				case 200:
					if (do_continue && output != stdout 
					#ifdef LIB_BBWGET
						&& (!p_lib_set || !p_lib_set->no_output_file)
					#endif
						)
						output = freopen(fname_out, "w", output);
					do_continue = 0;
					break;
				case 300:	/* redirection */
				case 301:
				case 302:
				case 303:
					break;
				case 206:
					if (do_continue)
						break;
					/*FALLTHRU*/
				default:
					chomp(buf);
					close_delete_and_die("server returned error %d: %s", atoi(s), buf);
			}

			/*
			 * Retrieve HTTP headers.
			 */
			while ((s = gethdr(buf, sizeof(buf), sfp, &n)) != NULL) {
				if (strcasecmp(buf, "content-length") == 0) {
					unsigned long value;
					if (safe_strtoul(s, &value)) {
						close_delete_and_die("content-length %s is garbage", s);
					}
					wget_filesize(pwget) = value;
					got_clen = 1;
					continue;
				}
				if (strcasecmp(buf, "transfer-encoding") == 0) {
					if (strcasecmp(s, "chunked") == 0) {
						wget_chunked(pwget) = got_clen = 1;
					} else {
						close_delete_and_die("server wants to do %s transfer encoding", s);
					}
				}
				if (strcasecmp(buf, "location") == 0) {
					if (s[0] == '/')
						target.path = bb_xstrdup(s+1);
					else {
						parse_url(bb_xstrdup(s), &target);
						if (use_proxy == 0) {
							server.host = target.host;
							server.port = target.port;
						}
					#ifdef LIB_BBWGET_FOR_THREAD
						bb_lookup_host_for_thread(&s_in, server.host);
					#else
						bb_lookup_host(&s_in, server.host);
					#endif
						s_in.sin_port = server.port;
						break;
					}
				}
			}
		} while(status >= 300);

		dfp = sfp;
	}
	else
	{
		/*
		 *  FTP session
		 */
		if (! target.user)
			target.user = bb_xstrdup("anonymous:busybox@");

		sfp = open_socket(&s_in, ifname);
		if (ftpcmd(NULL, NULL, sfp, buf) != 220)
			close_delete_and_die("%s", buf+4);

		/*
		 * Splitting username:password pair,
		 * trying to log in
		 */
		s = strchr(target.user, ':');
		if (s)
			*(s++) = '\0';
		switch(ftpcmd("USER ", target.user, sfp, buf)) {
			case 230:
				break;
			case 331:
				if (ftpcmd("PASS ", s, sfp, buf) == 230)
					break;
				/* FALLTHRU (failed login) */
			default:
				close_delete_and_die("ftp login: %s", buf+4);
		}

		ftpcmd("CDUP", NULL, sfp, buf);
		ftpcmd("TYPE I", NULL, sfp, buf);

		/*
		 * Querying file size
		 */
		if (ftpcmd("SIZE /", target.path, sfp, buf) == 213) {
			unsigned long value;
			if (safe_strtoul(buf+4, &value)) {
				close_delete_and_die("SIZE value is garbage");
			}
			wget_filesize(pwget) = value;
			got_clen = 1;
		}

		/*
		 * Entering passive mode
		 */
		if (ftpcmd("PASV", NULL, sfp, buf) !=  227)
			close_delete_and_die("PASV: %s", buf+4);
		s = strrchr(buf, ',');
		*s = 0;
		port = atoi(s+1);
		s = strrchr(buf, ',');
		port += atoi(s+1) * 256;
		s_in.sin_port = htons(port);
		dfp = open_socket(&s_in, ifname);

		if (do_continue) {
			sprintf(buf, "REST %ld", beg_range);
			if (ftpcmd(buf, NULL, sfp, buf) != 350) {
				if (output != stdout 
				#ifdef LIB_BBWGET
					&& (!p_lib_set || !p_lib_set->no_output_file)
				#endif
					)
					output = freopen(fname_out, "w", output);
				do_continue = 0;
			} else
				wget_filesize(pwget) -= beg_range;
		}

		if (ftpcmd("RETR /", target.path, sfp, buf) > 150)
			close_delete_and_die("RETR: %s", buf+4);
	}

	/*
	 * Retrieve file
	 */
	if (wget_chunked(pwget)) {
		fgets(buf, sizeof(buf), dfp);
		wget_filesize(pwget) = strtol(buf, (char **) NULL, 16);
	}

#ifdef LIB_BBWGET
	if(p_lib_set)
		p_lib_set->info.targe_file_size = wget_filesize(pwget);
#endif
    if (just_get_file_size == TRUE) {
        printf("filesize:%lld\n", wget_filesize(pwget));
        return EXIT_SUCCESS;
    }

#ifdef CONFIG_FEATURE_WGET_STATUSBAR
	if (quiet_flag==FALSE)
		progressmeter(-1);
#endif


	do {
		while ((wget_filesize(pwget) > 0 || !got_clen) && (n = safe_fread(buf, 1, ((wget_chunked(pwget) || got_clen) && (wget_filesize(pwget) < sizeof(buf)) ? wget_filesize(pwget) : sizeof(buf)), dfp)) > 0) 
		{
		#ifdef LIB_BBWGET
			if(p_lib_set){
			#ifdef LIB_BBWGET_FOR_THREAD
				if(p_lib_set->need_exit){
					close_and_delete_outfile(output, fname_out, do_continue);
					fclose(sfp);
					if ((use_proxy == 0) && target.is_ftp)
						fclose(dfp);
					printf("bbwget_thread %x need exit \n", (unsigned int)pthread_self());
					return EXIT_SUCCESS;
				}
			#endif
				if(p_lib_set->output_write){
					if(p_lib_set->output_write(buf, n, p_lib_set) != n)
						bb_perror_msg_and_die("write error");
				}
				else if(!p_lib_set->no_output_file){
					if (safe_fwrite(buf, 1, n, output) != n)
						bb_perror_msg_and_die("write error");
				}
			}
		#else
			if (safe_fwrite(buf, 1, n, output) != n) {
				bb_perror_msg_and_die("write error");
			}
		#endif
		
#ifdef CONFIG_FEATURE_WGET_STATUSBAR
			statbytes+=n;
#endif
			if (got_clen) {
				wget_filesize(pwget) -= n;
			}
		}

		if (wget_chunked(pwget)) {
			safe_fgets(buf, sizeof(buf), dfp); /* This is a newline */
			safe_fgets(buf, sizeof(buf), dfp);
			wget_filesize(pwget) = strtol(buf, (char **) NULL, 16);
			if (wget_filesize(pwget)==0) {
				wget_chunked(pwget) = 0; /* all done! */
			}
		}

		if (n == 0 && ferror(dfp)) {
			bb_perror_msg_and_die("network read error");
		}
	} while (wget_chunked(pwget));
#ifdef CONFIG_FEATURE_WGET_STATUSBAR
	if (quiet_flag==FALSE)
		progressmeter(1);
#endif
	if ((use_proxy == 0) && target.is_ftp) {
		fclose(dfp);
		if (ftpcmd(NULL, NULL, sfp, buf) != 226)
			bb_error_msg_and_die("ftp error: %s", buf+4);
		ftpcmd("QUIT", NULL, sfp, buf);
	}

	return EXIT_SUCCESS;
}


void parse_url(char *url, struct wg_host_info *h)
{
	char *cp, *sp, *up, *pp;

	if (strncmp(url, "http://", 7) == 0) {
		h->port = bb_lookup_port("http", "tcp", 80);
		h->host = url + 7;
		h->is_ftp = 0;
	} else if (strncmp(url, "ftp://", 6) == 0) {
		h->port = bb_lookup_port("ftp", "tfp", 21);
		h->host = url + 6;
		h->is_ftp = 1;
	} else
		bb_error_msg_and_die("not an http or ftp url: %s", url);

	sp = strchr(h->host, '/');
	if (sp) {
		*sp++ = '\0';
		h->path = sp;
	} else
		h->path = bb_xstrdup("");

	up = strrchr(h->host, '@');
	if (up != NULL) {
		h->user = h->host;
		*up++ = '\0';
		h->host = up;
	} else
		h->user = NULL;

	pp = h->host;

#ifdef CONFIG_FEATURE_WGET_IP6_LITERAL
	if (h->host[0] == '[') {
		char *ep;

		ep = h->host + 1;
		while (*ep == ':' || isxdigit (*ep))
			ep++;
		if (*ep == ']') {
			h->host++;
			*ep = '\0';
			pp = ep + 1;
		}
	}
#endif

	cp = strchr(pp, ':');
	if (cp != NULL) {
		*cp++ = '\0';
		h->port = htons(atoi(cp));
	}
}


FILE *open_socket(struct sockaddr_in *s_in, char *ifname)
{
	FILE *fp;

	int sk = 0;
    
    sk = socket(AF_INET, SOCK_STREAM, 0);
	int bufsize;
    bufsize = 256*1024;
#ifdef SO_RCVBUF
      setsockopt (sk, SOL_SOCKET, SO_RCVBUF,(void *)&bufsize, (socklen_t)sizeof (bufsize));
#endif
	if (ifname && strlen(ifname) && setsockopt(sk, SOL_SOCKET, SO_BINDTODEVICE, ifname,strlen(ifname) + 1)<0){
		close(sk);
		bb_perror_msg_and_die("BINDTODEVICE false");
	}

	if (connect(sk, (struct sockaddr *)s_in, sizeof(struct sockaddr_in)) < 0) {
		close(sk);
		bb_perror_msg_and_die("Unable to connect to remote host (%s)",
				inet_ntoa(s_in->sin_addr));
	}

	fp = fdopen(sk, "r+");
	if (fp == NULL) {
		close(sk);
		bb_perror_msg_and_die("fdopen()");
    }

	return fp;
}


char *gethdr(char *buf, size_t bufsiz, FILE *fp, int *istrunc)
{
	char *s, *hdrval;
	int c;

	*istrunc = 0;

	/* retrieve header line */
	if (fgets(buf, bufsiz, fp) == NULL)
		return NULL;

	/* see if we are at the end of the headers */
	for (s = buf ; *s == '\r' ; ++s)
		;
	if (s[0] == '\n')
		return NULL;

	/* convert the header name to lower case */
	for (s = buf ; isalnum(*s) || *s == '-' ; ++s)
		*s = tolower(*s);

	/* verify we are at the end of the header name */
	if (*s != ':')
		bb_error_msg_and_die("bad header line: %s", buf);

	/* locate the start of the header value */
	for (*s++ = '\0' ; *s == ' ' || *s == '\t' ; ++s)
		;
	hdrval = s;

	/* locate the end of header */
	while (*s != '\0' && *s != '\r' && *s != '\n')
		++s;

	/* end of header found */
	if (*s != '\0') {
		*s = '\0';
		return hdrval;
	}

	/* Rats!  The buffer isn't big enough to hold the entire header value. */
	while (c = getc(fp), c != EOF && c != '\n')
		;
	*istrunc = 1;
	return hdrval;
}

static int ftpcmd(char *s1, char *s2, FILE *fp, char *buf)
{
	if (s1) {
		if (!s2) s2="";
		fprintf(fp, "%s%s\r\n", s1, s2);
		fflush(fp);
	}

	do {
		char *buf_ptr;

		if (fgets(buf, 510, fp) == NULL) {
			bb_perror_msg_and_die("fgets()");
		}
		buf_ptr = strstr(buf, "\r\n");
		if (buf_ptr) {
			*buf_ptr = '\0';
		}
	} while (! isdigit(buf[0]) || buf[3] != ' ');

	return atoi(buf);
}

#ifdef CONFIG_FEATURE_WGET_STATUSBAR
/* Stuff below is from BSD rcp util.c, as added to openshh.
 * Original copyright notice is retained at the end of this file.
 *
 */


static int getttywidth(void)
{
	int width=0;
	get_terminal_width_height(0, &width, NULL);
	return (width);
}

static void updateprogressmeter(int ignore)
{
	int save_errno = errno;

	progressmeter(0);
	errno = save_errno;
}

static void alarmtimer(int wait)
{
	struct itimerval itv;

	itv.it_value.tv_sec = wait;
	itv.it_value.tv_usec = 0;
	itv.it_interval = itv.it_value;
	setitimer(ITIMER_REAL, &itv, NULL);
}

static void progressmeter(
#ifdef LIB_BBWGET
		bbwget_t *pwget, 
#endif
	int flag)
{
	static const char prefixes[] = " KMGTP";
	static struct timeval lastupdate;
	static off_t lastsize, totalsize;
	struct timeval now, td, wait;
	off_t cursize, abbrevsize;
	double elapsed;
	int ratio, barlength, i, remaining;
	char buf[256];

	if (flag == -1) {
		(void) gettimeofday(&start, (struct timezone *) 0);
		lastupdate = start;
		lastsize = 0;
		totalsize = wget_filesize(pwget); /* as filesize changes.. */
	}

	(void) gettimeofday(&now, (struct timezone *) 0);
	cursize = statbytes;
	if (totalsize != 0 && !wget_chunked(pwget)) {
		ratio = 100.0 * cursize / totalsize;
		ratio = MAX(ratio, 0);
		ratio = MIN(ratio, 100);
	} else
		ratio = 100;

	snprintf(buf, sizeof(buf), "\r%-20.20s %3d%% ", curfile, ratio);
	barlength = getttywidth() - 51;
	if (barlength > 0) {
		i = barlength * ratio / 100;
		snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf),
			 "|%.*s%*s|", i,
			 "*****************************************************************************"
			 "*****************************************************************************",
			 barlength - i, "");
	}
	i = 0;
	abbrevsize = cursize;
	while (abbrevsize >= 100000 && i < sizeof(prefixes)) {
		i++;
		abbrevsize >>= 10;
	}
	snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), " %5d %c%c ",
	     (int) abbrevsize, prefixes[i], prefixes[i] == ' ' ? ' ' :
		 'B');

	timersub(&now, &lastupdate, &wait);
	if (cursize > lastsize) {
		lastupdate = now;
		lastsize = cursize;
		if (wait.tv_sec >= STALLTIME) {
			start.tv_sec += wait.tv_sec;
			start.tv_usec += wait.tv_usec;
		}
		wait.tv_sec = 0;
	}
	timersub(&now, &start, &td);
	elapsed = td.tv_sec + (td.tv_usec / 1000000.0);

	if (wait.tv_sec >= STALLTIME) {
		snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf),
			 " - stalled -");
#if 0
		printf("\nget data error,wget exit\n");
		exit(-1);
#endif
	} else if (statbytes <= 0 || elapsed <= 0.0 || cursize > totalsize || wget_chunked(pwget)) {
		snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf),
			 "   --:-- ETA");
	} else {
		remaining = (int) (totalsize / (statbytes / elapsed) - elapsed);
		i = remaining / 3600;
		if (i)
			snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf),
				 "%2d:", i);
		else
			snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf),
				 "   ");
		i = remaining % 3600;
		snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf),
			 "%02d:%02d ETA", i / 60, i % 60);
	}
	write(STDERR_FILENO, buf, strlen(buf));
	
	if (flag == -1) {
		struct sigaction sa;
		sa.sa_handler = updateprogressmeter;
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = SA_RESTART;
		sigaction(SIGALRM, &sa, NULL);
		alarmtimer(1);
	} else if (flag == 1) {
		alarmtimer(0);
		statbytes = 0;
		putc('\n', stderr);
	}
}
#endif

/* Original copyright notice which applies to the CONFIG_FEATURE_WGET_STATUSBAR stuff,
 * much of which was blatantly stolen from openssh.  */

/*-
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. <BSD Advertising Clause omitted per the July 22, 1999 licensing change
 *		ftp://ftp.cs.berkeley.edu/pub/4bsd/README.Impt.License.Change>
 *
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	$Id: wget.c,v 1.75 2004/10/08 08:27:40 andersen Exp $
 */

#ifdef LIB_BBWGET
int lib_bbwget_main(bb_wget_lib_t *set, int argc, char **argv)
{
	static bbwget_t pwget;
	memset(&pwget, 0, sizeof(bbwget_t));
	pwget.lib_set = set;
	return wget_main(&pwget, argc, argv);
}

static int output_write_to_wf_buffer(void *ptr, int size, struct bb_wget_lib_s *pwgetlib)
{
	struct wf_buffer *dst = (struct wf_buffer *)(pwgetlib->extend_ptr);

	wf_buffer_append(dst, ptr, size);
	return size;
}

int lib_bbwget_to_wf_buffer(int argc, char **argv, struct wf_buffer **out, unsigned int buffer_size)
{
	static bbwget_t pwget;
	bb_wget_lib_t *pwgetlib = NULL;
	struct wf_buffer *p = NULL;
	int ret = 0;

	if(argc < 0 || !argv || !out || !buffer_size)
		return -1;
	memset(&pwget, 0, sizeof(bbwget_t));

	pwgetlib = (bb_wget_lib_t *)malloc(sizeof(bb_wget_lib_t));
	if(!pwgetlib)
		return -1;
	memset(pwgetlib, 0, sizeof(sizeof(bbwget_t)));

	p = *out;
	if(p && p->data){
		pwgetlib->extend_ptr = p;
		pwgetlib->set_beg_range_bytes = p->len;
	}
	else{
		pwgetlib->extend_ptr = wf_buffer_malloc(NULL, buffer_size);
		if(!pwgetlib->extend_ptr){
			free(pwgetlib);
			return -1;
		}
		*out = pwgetlib->extend_ptr;
		pwgetlib->set_beg_range_bytes = 0;
	}

	pwgetlib->no_output_file = 1;
	pwgetlib->use_sigsetjmp = 1;
	pwgetlib->output_write = output_write_to_wf_buffer;
	pwget.lib_set = pwgetlib;

	ret = wget_main(&pwget, argc, argv);
	free(pwgetlib);
	return ret;
}

int lib_bbwget_check_url_exist(char *url)
{
	static bbwget_t pwget;
	bb_wget_lib_t *pwgetlib = NULL;
	int ret = 0, exist = 0;
	int argc = -1;
	char *argv[5] = {NULL};

	if(!url)
		return -1;
	memset(&pwget, 0, sizeof(bbwget_t));

	pwgetlib = (bb_wget_lib_t *)malloc(sizeof(bb_wget_lib_t));
	if(!pwgetlib)
		return -1;
	memset(pwgetlib, 0, sizeof(sizeof(bbwget_t)));

	pwgetlib->no_output_file = 1;
	pwgetlib->use_sigsetjmp = 1;
	pwget.lib_set = pwgetlib;

	argv[++argc] = "bbwget";
	argv[++argc] = "-s";
	argv[++argc] = url;
	argv[++argc] = NULL;
	
	ret = wget_main(&pwget, argc, argv);
	if(pwgetlib->info.targe_file_size > 0)
		exist = 1;
	free(pwgetlib);
	if(exist)
		return 1;
	else
		return ret == EXIT_SUCCESS ? 0 : -2;
}

#ifdef LIB_BBWGET_FOR_THREAD

// 0: dead ; >0: alive ; <0: error
int wf_get_thread_state(pthread_t *p_tid)
{
	int rc = pthread_kill(*p_tid,0);
	if(rc == ESRCH)
		return 0;
	else if(rc == EINVAL)
		return -1;
	else
		return 1;
}


static void bbwget_t_free(bbwget_t *ptr, int free_self)
{
	int i = 0;
	
	if(!ptr)
		return;

	if(ptr->thread_argv){
		if(ptr->thread_argc > 0){
			for(i=0; i<ptr->thread_argc; i++)
				free(ptr->thread_argv[i]);
		}
		free(ptr->thread_argv);
	}

	if(free_self)
		free(ptr);
	else
		memset(ptr, 0, sizeof(bbwget_t));
}

void bb_wget_thread_t_free(bb_wget_thread_t *ptr, int free_self)
{
	if(!ptr)
		return;

	if(ptr->private_data)
		bbwget_t_free((bbwget_t *)ptr->private_data, 1);

	if(ptr->extend_ptr_free && ptr->extend_ptr)
		ptr->extend_ptr_free(ptr->extend_ptr);

	if(free_self)
		free(ptr);
	else
		memset(ptr, 0, sizeof(bb_wget_thread_t));
}

static void *bbwget_thread_func(void *arg)
{
	bbwget_t *pwget = (bbwget_t *)arg;
	sigset_t tsigs;

	if(!pwget)
		return NULL;

	sigfillset(&tsigs);
	sigdelset(&tsigs, BBWGET_THREAD_SIGQUIT);
#if 1
	sigdelset(&tsigs, SIGQUIT);
	sigdelset(&tsigs, SIGTERM);
#endif
	pthread_sigmask(SIG_SETMASK, &tsigs, NULL);
#ifdef PTHREAD_CANCEL_ENABLE
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
#endif
	do{
		wget_main(pwget, pwget->thread_argc, pwget->thread_argv);
	}while(pwget->lib_set && pwget->lib_set->is_loop);

	pwget->exited = 1;
	//printf("bbwget_thread %x exit \n", (unsigned int)pthread_self());
	return NULL;
}

void lib_bbwget_thread_destroy(bb_wget_thread_t *bbwget_thd, int wait)
{
	int rc = 0;
	bbwget_t *pwget = NULL;
	if(!bbwget_thd)
		return;

	pwget = (bbwget_t *)bbwget_thd->private_data;
	rc = pthread_kill(bbwget_thd->tid,0);
	if(rc != ESRCH){
		if(pwget && pwget->lib_set){
			pwget->lib_set->need_exit = 1;
			pwget->lib_set->is_loop = 0;
		}
		else{
		#ifdef PTHREAD_CANCEL_ENABLE
			pthread_cancel(bbwget_thd->tid);
		#else
			pthread_kill(bbwget_thd->tid,BBWGET_THREAD_SIGQUIT);
		#endif
		}
		
		if(wait)
			pthread_join(bbwget_thd->tid, NULL);
		else{
			while(1){
				if(pwget->exited)
					break;
				usleep(50000); // sleep 5 ms, wait bbwget_thread_func 
			}
		}
			
	}

	bb_wget_thread_t_free(bbwget_thd, 1);
}

// 0: dead ; >0: alive ; <0: error
int lib_bbwget_thread_state(bb_wget_thread_t *bbwget_thd)
{
	int rc = pthread_kill(bbwget_thd->tid,0);
	if(rc == ESRCH)
		return 0;
	else if(rc == EINVAL)
		return -1;
	else
		return 1;
}

bb_wget_thread_t *lib_bbwget_thread(bb_wget_lib_t *set, int argc, char **argv, pthread_attr_t	*attr)
{
	bbwget_t *pwget = NULL;
	bb_wget_thread_t *bbwget_thd = NULL;
	int i = 0;
	
	if(argc < 0 || !argv)
		return NULL;

	bbwget_thd = (bb_wget_thread_t *)malloc(sizeof(bb_wget_thread_t));
	if(!bbwget_thd)
		goto ERR_END;
	memset(bbwget_thd, 0, sizeof(bb_wget_thread_t));
	pwget = (bbwget_t *)malloc(sizeof(bbwget_t));
	if(!pwget)
		goto ERR_END;
	memset(pwget, 0, sizeof(bbwget_t));
	bbwget_thd->private_data = pwget;
	pwget->lib_set = set;
	pwget->thread_argv = (char **)malloc(sizeof(char *) * (argc+1));
	if(!pwget->thread_argv)
		goto ERR_END;
	memset(pwget->thread_argv, 0, sizeof(char *) * (argc+1));
	pwget->thread_argc = argc;
	for(i=0; i<argc; i++){
		pwget->thread_argv[i] = strdup(argv[i]);
		if(!pwget->thread_argv[i])
			goto ERR_END;
	}
	
	if(pthread_create(&bbwget_thd->tid, attr, bbwget_thread_func, pwget) < 0)
		goto ERR_END;

	return bbwget_thd;

ERR_END:
	bb_wget_thread_t_free(bbwget_thd, 1);
	return NULL;
}

bb_wget_thread_t *lib_bbwget_to_wf_buffer_thread(int argc, char **argv, pthread_attr_t	*attr, struct wf_buffer **out, unsigned int buffer_size)
{
	bb_wget_lib_t *pwgetlib = NULL;
	struct wf_buffer *p = NULL;
	bb_wget_thread_t *bbwget_thd = NULL;

	if(argc < 0 || !argv || !out || !buffer_size)
		return NULL;

	pwgetlib = (bb_wget_lib_t *)malloc(sizeof(bb_wget_lib_t));
	if(!pwgetlib)
		return NULL;
	memset(pwgetlib, 0, sizeof(sizeof(bbwget_t)));

	p = *out;
	if(p && p->data){
		pwgetlib->extend_ptr = p;
		pwgetlib->set_beg_range_bytes = p->len;
	}
	else{
		pwgetlib->extend_ptr = wf_buffer_malloc(NULL, buffer_size);
		if(!pwgetlib->extend_ptr){
			free(pwgetlib);
			return NULL;
		}
		*out = pwgetlib->extend_ptr;
		pwgetlib->set_beg_range_bytes = 0;
	}

	pwgetlib->no_output_file = 1;
	pwgetlib->use_sigsetjmp = 0;
	pwgetlib->is_loop = 0;
	pwgetlib->output_write = output_write_to_wf_buffer;

	bbwget_thd = lib_bbwget_thread(pwgetlib, argc, argv, attr);
	if(bbwget_thd){
		bbwget_thd->extend_ptr = pwgetlib;
		bbwget_thd->extend_ptr_free = free;
	}
	else
		free(pwgetlib);
	return bbwget_thd;
}

int lib_bbwget_check_url_exist_wait_100usec(char * url, unsigned int max_count)
{
	bb_wget_lib_t *pwgetlib = NULL;
	bb_wget_thread_t *bbwget_thd = NULL;
	int exist = 0;
	int argc = -1;
	char *argv[5] = {NULL};
	unsigned int time_count = 0;
#ifndef NOT_USE_PTHREAD_CREATE_DETACHED
	pthread_attr_t attr;
#endif
	if(!url)
		return -1;

	pwgetlib = (bb_wget_lib_t *)malloc(sizeof(bb_wget_lib_t));
	if(!pwgetlib)
		return -1;
	memset(pwgetlib, 0, sizeof(sizeof(bbwget_t)));

	pwgetlib->no_output_file = 1;

	argv[++argc] = "bbwget";
	argv[++argc] = "-s";
	argv[++argc] = url;
	argv[++argc] = NULL;
#ifdef NOT_USE_PTHREAD_CREATE_DETACHED
	bbwget_thd = lib_bbwget_thread(pwgetlib, argc, argv, NULL);
#else
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	bbwget_thd = lib_bbwget_thread(pwgetlib, argc, argv, &attr);
	pthread_attr_destroy(&attr);
#endif
	if(bbwget_thd){
		bbwget_thd->extend_ptr = pwgetlib;
		bbwget_thd->extend_ptr_free = free;
	}
	else{
		free(pwgetlib);
		return -2;
	}

	while(1){
		if(pwgetlib->info.targe_file_size > 0){
			exist = 1;
			break;
		}
		if(time_count >= max_count)
			break;
		usleep(100000);
		++time_count;
	}
#ifdef NOT_USE_PTHREAD_CREATE_DETACHED
	lib_bbwget_thread_destroy(bbwget_thd, 1);
#else
	lib_bbwget_thread_destroy(bbwget_thd, 0);
#endif
	return exist;
}



#endif

#else
int main(int argc, char **argv)
{
	return wget_main(argc, argv);
}
#endif

/*
Local Variables:
c-file-style: "linux"
c-basic-offset: 4
tab-width: 4
End:
*/
