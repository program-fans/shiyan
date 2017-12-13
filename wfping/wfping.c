#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <netdb.h>
#include <errno.h>
#include <ctype.h>
#include <sched.h>

//#include "wf_ip_icmp.h"

#include "wfping.h"
#include "wf_misc.h"

#ifdef LIB_WFPING_FOR_THREAD
#include <pthread.h>
#endif


#define WFPING_PERROR(str) perror(str)
#define WFPING_ERROR(fmt, args...) fprintf(stderr, fmt, ##args)
#define WFPING_DEBUG(fmt, args...) printf(fmt, ##args)


#if 0
#define wfping_printf(fmt, args...) printf(fmt, ##args)
#define wfping_fflush(fp) fflush(fp)
#define wfping_putchar(c) putchar(c)
#else
#define wfping_printf(fmt, args...)
#define wfping_fflush(fp)
#define wfping_putchar(c)
#endif


#ifndef LIB_WFPING
static wfping_t g_wfp;
#endif

#ifdef LIB_WFPING_FOR_THREAD
static pthread_mutex_t	lookup_host_mutex;
static int lookup_host_init = 0;
static struct hostent *wfp_gethostbyaddr(char * addr, int len, int type)
{
	struct hostent *hp = NULL;
	
	if(!lookup_host_init){
		pthread_mutex_init(&lookup_host_mutex, NULL);
		lookup_host_init = 1;
	}
	pthread_mutex_lock(&lookup_host_mutex);
	hp = gethostbyaddr(addr, len, type);
	pthread_mutex_unlock(&lookup_host_mutex);

	return hp;
}
static struct hostent *wfp_gethostbyname(char *name)
{
	struct hostent *hp = NULL;
	
	if(!lookup_host_init){
		pthread_mutex_init(&lookup_host_mutex, NULL);
		lookup_host_init = 1;
	}
	pthread_mutex_lock(&lookup_host_mutex);
	hp = gethostbyname(name);
	pthread_mutex_unlock(&lookup_host_mutex);

	return hp;
}
#else
#define wfp_gethostbyaddr gethostbyaddr
#define wfp_gethostbyname gethostbyname
#endif

static void wfping_usage()
{
}

static void default_set_wfping(wfping_t *pwfp)
{
	memset(pwfp, 0, sizeof(wfping_t));
	pwfp->interval_ms = 1000;
	pwfp->datalen = 32;
	pwfp->pmtudisc = -1;

	pwfp->icmp_req = 1;
}

static int init_wfping_by_arg(wfping_t *pwfp, int argc, char **argv)
{
	struct arg_parse_t wfping_arglist[] = {
		{"-i", &(pwfp->interval_ms), 0, 1, NULL, ARG_VALUE_TYPE_INT, 0, NULL},
		{"-S", &(pwfp->sndbuf_size), 0, 1, NULL, ARG_VALUE_TYPE_INT, 0, NULL},
		{"-s", &(pwfp->datalen), 0, 1, NULL, ARG_VALUE_TYPE_INT, 0, NULL},
		{"-I", &(pwfp->device), 0, 1, arg_deal_default, 0, 0, NULL},
		{"-c", &(pwfp->npackets), 0, 1, NULL, ARG_VALUE_TYPE_INT, 0, NULL},
		{"-w", &(pwfp->deadline), 0, 1, NULL, ARG_VALUE_TYPE_INT, 0, NULL},
		arg_parse_t_init_null
	};
	int new_argc = 0;
	char **new_argv = (char **)malloc(sizeof(char *) * argc);
	char **tmp_argv;
	struct hostent *hp = NULL;

	if(!new_argv){
		WFPING_PERROR("wfping: malloc");
		return -1;
	}
	memset(new_argv, 0, sizeof(char *) * argc);
	if(arg_parse(argc, argv, wfping_arglist, &new_argc, new_argv) < 0){
		wfping_usage();
		return -1;
	}

	--new_argc;
	tmp_argv = new_argv + 1;
	while(new_argc > 0){
		pwfp->target_host = *tmp_argv;
		memset(&(pwfp->whereto), 0, sizeof(pwfp->whereto));
		pwfp->whereto.sin_family = AF_INET;
		if (inet_aton(pwfp->target_host, &(pwfp->whereto.sin_addr)) == 1) {
			strncpy(pwfp->ip_name, pwfp->target_host, sizeof(pwfp->ip_name)-1);
			if(new_argc == 1)
				pwfp->options |= F_NUMERIC;
		}
		else{
			hp = wfp_gethostbyname(pwfp->target_host);
			if (!hp) {
				WFPING_ERROR("wfping: unknown host %s\n", pwfp->target_host);
				return -1;
			}
			memcpy(&(pwfp->whereto.sin_addr), hp->h_addr, 4);
			strncpy(pwfp->ip_name, hp->h_name, sizeof(pwfp->ip_name)-1);
		}
		if (new_argc > 1)
			pwfp->route[pwfp->nroute++] = pwfp->whereto.sin_addr.s_addr;
		--new_argc;
		++tmp_argv;
	}

	if(!pwfp->target_host)
		wfping_usage();
	free(new_argv);
	return 0;
}

static int check_and_set_wfping(wfping_t *pwfp)
{
	int ret = 0, i = 0;
	int probe_fd = -1;
	struct ifreq ifr;

	if(pwfp->deadline < 0){
		WFPING_ERROR("wfping: bad wait time.\n");
		return -1;
	}
	if(pwfp->npackets < 0){
		WFPING_ERROR("ping: bad number of packets to transmit.\n");
		return -1;
	}
	
	if(pwfp->device){
		if (inet_pton(AF_INET, optarg, &(pwfp->source.sin_addr)) > 0)
			pwfp->options |= F_STRICTSOURCE;
	}

	if (pwfp->source.sin_addr.s_addr == 0) {
		socklen_t alen;
		struct sockaddr_in dst = pwfp->whereto;
		probe_fd = socket(AF_INET, SOCK_DGRAM, 0);

		if (probe_fd < 0) {
			WFPING_PERROR("socket");
			return -1;
		}
		if (pwfp->device) {
			memset(&ifr, 0, sizeof(ifr));
			strncpy(ifr.ifr_name, pwfp->device, IFNAMSIZ-1);
			if (setsockopt(probe_fd, SOL_SOCKET, SO_BINDTODEVICE, pwfp->device, strlen(pwfp->device)+1) == -1) {
				if (IN_MULTICAST(ntohl(dst.sin_addr.s_addr))) {
					struct ip_mreqn imr;
					if (ioctl(probe_fd, SIOCGIFINDEX, &ifr) < 0) {
						WFPING_ERROR("wfping: unknown iface %s\n", pwfp->device);
						ret = -1;
						goto END;
					}
					memset(&imr, 0, sizeof(imr));
					imr.imr_ifindex = ifr.ifr_ifindex;
					if (setsockopt(probe_fd, SOL_IP, IP_MULTICAST_IF, &imr, sizeof(imr)) == -1) {
						WFPING_ERROR("wfping: IP_MULTICAST_IF");
						ret = -1;
						goto END;
					}
				}
			}
		}

		if (pwfp->settos && setsockopt(probe_fd, IPPROTO_IP, IP_TOS, (char *)&(pwfp->settos), sizeof(int)) < 0)
			WFPING_PERROR("Warning: error setting QOS sockopts");
		dst.sin_port = htons(1025);
		if (pwfp->nroute > 0)
			dst.sin_addr.s_addr = pwfp->route[0];
		if (connect(probe_fd, (struct sockaddr*)&dst, sizeof(dst)) == -1) {
			if (errno == EACCES) {
				if (pwfp->broadcast_pings == 0) {
					WFPING_ERROR("Do you want to ping broadcast? Then -b\n");
					ret = -1;
					goto END;
				}
				WFPING_ERROR("WARNING: pinging broadcast address\n");
				if (setsockopt(probe_fd, SOL_SOCKET, SO_BROADCAST,
					&(pwfp->broadcast_pings), sizeof(pwfp->broadcast_pings)) < 0) {
					WFPING_PERROR ("can't set broadcasting");
					ret = -1;
					goto END;
				}
				if (connect(probe_fd, (struct sockaddr*)&dst, sizeof(dst)) == -1) {
					WFPING_PERROR("connect");
					ret = -1;
					goto END;
				}
			} 
			else {
				WFPING_PERROR("connect");
				ret = -1;
				goto END;
			}
		}
		alen = sizeof(pwfp->source);
		if (getsockname(probe_fd, (struct sockaddr*)&(pwfp->source), &alen) == -1) {
			WFPING_PERROR("getsockname");
			ret = -1;
			goto END;
		}
		pwfp->source.sin_port = 0;
		close(probe_fd);
	} 

	if (pwfp->whereto.sin_addr.s_addr == 0)
		pwfp->whereto.sin_addr.s_addr = pwfp->source.sin_addr.s_addr;

	if (pwfp->device) {
		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, pwfp->device, IFNAMSIZ-1);
		if (ioctl(pwfp->icmp_sock, SIOCGIFINDEX, &ifr) < 0) {
			WFPING_ERROR("wfping: unknown iface %s\n", pwfp->device);
			ret = -1;
			goto END;
		}
	}

	if (pwfp->broadcast_pings || IN_MULTICAST(ntohl(pwfp->whereto.sin_addr.s_addr))) {
	#ifndef LIB_WFPING_FOR_THREAD
		if (pwfp->uid) {
			if (pwfp->interval_ms < 1000) {
				WFPING_ERROR("wfping: broadcast ping with too short interval.\n");
				ret = -1;
				goto END;
			}
			if (pwfp->pmtudisc >= 0 && pwfp->pmtudisc != IP_PMTUDISC_DO) {
				WFPING_ERROR("wfping: broadcast ping does not fragment.\n");
				ret = -1;
				goto END;
			}
		}
	#endif
		if (pwfp->pmtudisc < 0)
			pwfp->pmtudisc = IP_PMTUDISC_DO;
	}

	if (pwfp->pmtudisc >= 0) {
	    if (setsockopt(pwfp->icmp_sock, SOL_IP, IP_MTU_DISCOVER, &(pwfp->pmtudisc), sizeof(pwfp->pmtudisc)) == -1) {
			WFPING_PERROR("wfping: IP_MTU_DISCOVER");
			ret = -1;
			goto END;
	    }
	}

	if ((pwfp->options & F_STRICTSOURCE) &&
	    bind(pwfp->icmp_sock, (struct sockaddr*)&(pwfp->source), sizeof(pwfp->source)) == -1) {
		WFPING_PERROR("bind");
		ret = -1;
		goto END;
	}

	
	int hold = 1;
	if (setsockopt(pwfp->icmp_sock, SOL_IP, IP_RECVERR, (char *)&hold, sizeof(hold)))
		WFPING_ERROR("WARNING: your kernel is veeery old. No problems.\n");

	char rspace[3 + 4 * NROUTES + 1];	// record route space 
	/* record route option */
	if (pwfp->options & F_RROUTE) {
		memset(rspace, 0, sizeof(rspace));
		rspace[0] = IPOPT_NOP;
		rspace[1+IPOPT_OPTVAL] = IPOPT_RR;
		rspace[1+IPOPT_OLEN] = sizeof(rspace)-1;
		rspace[1+IPOPT_OFFSET] = IPOPT_MINOFF;
		pwfp->optlen = 40;
		if (setsockopt(pwfp->icmp_sock, IPPROTO_IP, IP_OPTIONS, rspace, sizeof(rspace)) < 0) {
			WFPING_PERROR("wfping: record route");
			ret = -1;
			goto END;
		}
	}
	
	if (pwfp->options & F_TIMESTAMP) {
		memset(rspace, 0, sizeof(rspace));
		rspace[0] = IPOPT_TIMESTAMP;
		rspace[1] = (pwfp->ts_type==IPOPT_TS_TSONLY ? 40 : 36);
		rspace[2] = 5;
		rspace[3] = pwfp->ts_type;
		if (pwfp->ts_type == IPOPT_TS_PRESPEC) {
			rspace[1] = 4 + pwfp->nroute * 8;
			for (i=0; i<pwfp->nroute; i++)
				*(unsigned int *)&rspace[4+i*8] = pwfp->route[i];
		}
		if (setsockopt(pwfp->icmp_sock, IPPROTO_IP, IP_OPTIONS, rspace, rspace[1]) < 0) {
			rspace[3] = 2;
			if (setsockopt(pwfp->icmp_sock, IPPROTO_IP, IP_OPTIONS, rspace, rspace[1]) < 0) {
				WFPING_PERROR("wfping: ts option");
				ret = -1;
				goto END;
			}
		}
		pwfp->optlen = 40;
	}
	
	if (pwfp->options & F_SOURCEROUTE) {
		memset(rspace, 0, sizeof(rspace));
		rspace[0] = IPOPT_NOOP;
		rspace[1+IPOPT_OPTVAL] = (pwfp->options & F_SO_DONTROUTE) ? IPOPT_SSRR: IPOPT_LSRR;
		rspace[1+IPOPT_OLEN] = 3 + pwfp->nroute*4;
		rspace[1+IPOPT_OFFSET] = IPOPT_MINOFF;
		for (i=0; i<pwfp->nroute; i++)
		*(unsigned int *)&rspace[4+i*4] = pwfp->route[i];
		if (setsockopt(pwfp->icmp_sock, IPPROTO_IP, IP_OPTIONS, rspace, 4 + pwfp->nroute*4) < 0) {
			WFPING_PERROR("wfping: record route");
			ret = -1;
			goto END;
		}
		pwfp->optlen = 40;
	}

	/* Estimate memory eaten by single packet. It is rough estimate.
	* Actually, for small datalen's it depends on kernel side a lot. */
	hold = pwfp->datalen + 8;
	hold += ((hold+511)/512)*(pwfp->optlen + 20 + 16 + 64 + 160);
	if (!pwfp->sndbuf_size)
		pwfp->sndbuf_size = hold;
	setsockopt(pwfp->icmp_sock, SOL_SOCKET, SO_SNDBUF, (char *)&(pwfp->sndbuf_size), sizeof(pwfp->sndbuf_size));

	int rcvbuf;
	socklen_t tmplen = sizeof(hold);
	rcvbuf = hold;
	if(rcvbuf < 65536)
		hold = 65536;
	setsockopt(pwfp->icmp_sock, SOL_SOCKET, SO_RCVBUF, (char *)&hold, sizeof(hold));
	if (getsockopt(pwfp->icmp_sock, SOL_SOCKET, SO_RCVBUF, (char *)&hold, &tmplen) == 0){
		if (hold < rcvbuf)
			WFPING_ERROR("WARNING: probably, rcvbuf is not enough to hold preload.\n");
	}

	if (pwfp->broadcast_pings) {
		if (setsockopt(pwfp->icmp_sock, SOL_SOCKET, SO_BROADCAST,&pwfp->broadcast_pings, sizeof(pwfp->broadcast_pings)) < 0) {
			WFPING_PERROR ("wfping: can't set broadcasting");
			ret = -1;
			goto END;
		}
	}

	if (pwfp->options & F_NOLOOP) {
		int loop = 0;
		if (setsockopt(pwfp->icmp_sock, IPPROTO_IP, IP_MULTICAST_LOOP,&loop, 1) == -1) {
			WFPING_PERROR ("wfping: can't disable multicast loopback");
			ret = -1;
			goto END;
		}
	}
	if (pwfp->options & F_TTL) {
		int ittl = pwfp->ttl;
		if (setsockopt(pwfp->icmp_sock, IPPROTO_IP, IP_MULTICAST_TTL,&pwfp->ttl, 1) == -1) {
			WFPING_PERROR ("wfping: can't set multicast time-to-live");
			ret = -1;
			goto END;
		}
		if (setsockopt(pwfp->icmp_sock, IPPROTO_IP, IP_TTL,&ittl, sizeof(ittl)) == -1) {
			WFPING_PERROR ("wfping: can't set unicast time-to-live");
			ret = -1;
			goto END;
		}
	}

	if (pwfp->datalen > 0xFFFF - 8 - pwfp->optlen - 20) {
		if (pwfp->datalen > WFPING_MAXPACKET - 8 
		#ifndef LIB_WFPING_FOR_THREAD
			|| pwfp->uid
		#endif 
			) {
			WFPING_ERROR("Error: packet size %d is too large. Maximum is %d\n", pwfp->datalen, 0xFFFF-8-20-pwfp->optlen);
			ret = -1;
			goto END;
		}
		/* Allow small oversize to root yet. It will cause EMSGSIZE. */
		WFPING_ERROR("WARNING: packet size %d is too large. Maximum is %d\n", pwfp->datalen, 0xFFFF-8-20-pwfp->optlen);
	}

	if (pwfp->datalen >= sizeof(struct timeval))	/* can we time transfer */
		pwfp->timing = 1;
	
	int packlen = pwfp->datalen + MAXICMPLEN;
	pwfp->packet = (unsigned char *)malloc((u_int)packlen);
	if (!pwfp->packet) {
		WFPING_ERROR("wfping: out of memory.\n");
		ret = -1;
		//goto END;
	}  

END:
	if(probe_fd >= 0)
		close(probe_fd);
	return ret;
}

// Protocol independent setup
static int setup_icmp_sock(wfping_t *pwfp)
{
	int hold;
	struct timeval tv;

	if ((pwfp->options & F_FLOOD) && !(pwfp->options & F_INTERVAL))
		pwfp->interval_ms = 0;

	if (pwfp->interval_ms < MINUSERINTERVAL
	#ifndef LIB_WFPING_FOR_THREAD
		&& pwfp->uid
	#endif
		) {
		WFPING_ERROR("wfping: cannot flood; minimal interval, allowed for user, is %dms\n", MINUSERINTERVAL);
		return -1;
	}

	if (pwfp->interval_ms >= INT_MAX) {
		WFPING_ERROR("wfping: illegal interval\n");
		return -1;
	}

	hold = 1;
	if (pwfp->options & F_SO_DEBUG)
		setsockopt(pwfp->icmp_sock, SOL_SOCKET, SO_DEBUG, (char *)&hold, sizeof(hold));
	if (pwfp->options & F_SO_DONTROUTE)
		setsockopt(pwfp->icmp_sock, SOL_SOCKET, SO_DONTROUTE, (char *)&hold, sizeof(hold));

#ifdef SO_TIMESTAMP
	if (!(pwfp->options & F_LATENCY)) {
		int on = 1;
		if (setsockopt(pwfp->icmp_sock, SOL_SOCKET, SO_TIMESTAMP, &on, sizeof(on)))
			WFPING_ERROR("Warning: no SO_TIMESTAMP support, falling back to SIOCGSTAMP\n");
	}
#endif
	if (pwfp->options & F_MARK) {
		if (setsockopt(pwfp->icmp_sock, SOL_SOCKET, SO_MARK, &pwfp->mark, sizeof(pwfp->mark)) == -1) {
			/* we probably dont wanna exit since old kernels
			* dont support mark ..
			*/
			WFPING_ERROR("Warning: Failed to set mark %d\n", pwfp->mark);
		}
	}

	/* Set some SNDTIMEO to prevent blocking forever
	* on sends, when device is too slow or stalls. Just put limit
	* of one second, or "interval", if it is less.
	*/
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	if (pwfp->interval_ms < 1000) {
		tv.tv_sec = 0;
		tv.tv_usec = 1000 * SCHINT(pwfp->interval_ms);
	}
	setsockopt(pwfp->icmp_sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&tv, sizeof(tv));

	/* Set RCVTIMEO to "interval". Note, it is just an optimization
	* allowing to avoid redundant poll(). */
	tv.tv_sec = SCHINT(pwfp->interval_ms)/1000;
	tv.tv_usec = 1000*(SCHINT(pwfp->interval_ms)%1000);
	if (setsockopt(pwfp->icmp_sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv)))
		pwfp->options |= F_FLOOD_POLL;

	if (!(pwfp->options & F_PINGFILLED)) {
		int i;
		u_char *p = pwfp->outpack + 8;

		/* Do not forget about case of small datalen,
		* fill timestamp area too!
		*/
		for (i = 0; i < pwfp->datalen; ++i)
			*p++ = i;
	}

	gettimeofday(&pwfp->start_time, NULL);

	return 0;
}

static inline void wfp_tvsub(struct timeval *out, struct timeval *in)
{
	if ((out->tv_usec -= in->tv_usec) < 0) {
		--out->tv_sec;
		out->tv_usec += 1000000;
	}
	out->tv_sec -= in->tv_sec;
}

static int is_deadline(wfping_t *pwfp)
{
	if(pwfp->ntransmitted == 0)
		return 0;
	if((pwfp->cur_time.tv_sec - pwfp->start_time.tv_sec) >= pwfp->deadline)
		return 1;
	return 0;
}

static inline int in_flight(wfping_t *pwfp)
{
	__u16 diff = (__u16)pwfp->ntransmitted - pwfp->acked;
	return (diff<=0x7FFF) ? diff : pwfp->ntransmitted - pwfp->nreceived - pwfp->nerrors;
}

static inline void advance_ntransmitted(wfping_t *pwfp)
{
	pwfp->ntransmitted++;
	/* Invalidate acked, if 16 bit seq overflows. */
	if ((__u16)pwfp->ntransmitted - pwfp->acked > 0x7FFF)
		pwfp->acked = (__u16)pwfp->ntransmitted + 1;
}

static inline void update_interval(wfping_t *pwfp)
{
	int est = pwfp->rtt ? pwfp->rtt/8 : pwfp->interval_ms*1000;

	pwfp->interval_ms = (est+pwfp->rtt_addend+500)/1000;
	if ( pwfp->interval_ms < MINUSERINTERVAL
	#ifndef LIB_WFPING_FOR_THREAD
		&& pwfp->uid
	#endif
	)
		pwfp->interval_ms = MINUSERINTERVAL;
}

static inline void acknowledge(wfping_t *pwfp, __u16 seq)
{
	__u16 diff = (__u16)pwfp->ntransmitted - seq;
	if (diff <= 0x7FFF) {
		if ((__s16)(seq - pwfp->acked) > 0 ||
		    (__u16)pwfp->ntransmitted - pwfp->acked > 0x7FFF)
			pwfp->acked = seq;
	}
}

static void print_timestamp(wfping_t *pwfp)
{
	if (pwfp->options & F_PTIMEOFDAY) {
		struct timeval tv;
		gettimeofday(&tv, NULL);
		wfping_printf("[%lu.%06lu] ",
		       (unsigned long)tv.tv_sec, (unsigned long)tv.tv_usec);
	}
}

static char *wfp_pr_addr(wfping_t *pwfp, __u32 addr)
{
	struct hostent *hp;
	char *pbuf = NULL;
#ifdef LIB_WFPING_FOR_THREAD	
	if(pwfp->tmp_buf == NULL)
		pbuf = pwfp->tmp_buf = (char *)malloc(4096);
	if(pwfp->tmp_buf == NULL)
		return "";
#else
	static char buf[4096];
	pbuf = &buf[0];
#endif

	if ((pwfp->options & F_NUMERIC) ||
	    !(hp = wfp_gethostbyaddr((char *)&addr, 4, AF_INET)))
		sprintf(pbuf, "%s", inet_ntoa(*(struct in_addr *)&addr));
	else
		snprintf(pbuf, 4096, "%s (%s)", hp->h_name,
			 inet_ntoa(*(struct in_addr *)&addr));
	return pbuf;
}


static void pr_options(wfping_t *pwfp, unsigned char * cp, int hlen)
{
	int i, j;
	int optlen, totlen;
	unsigned char * optptr;

	totlen = hlen-sizeof(struct iphdr);
	optptr = cp;

	while (totlen > 0) {
		if (*optptr == IPOPT_EOL)
			break;
		if (*optptr == IPOPT_NOP) {
			totlen--;
			optptr++;
			wfping_printf("\nNOP");
			continue;
		}
		cp = optptr;
		optlen = optptr[1];
		if (optlen < 2 || optlen > totlen)
			break;

		switch (*cp) {
		case IPOPT_SSRR:
		case IPOPT_LSRR:
			wfping_printf("\n%cSRR: ", *cp==IPOPT_SSRR ? 'S' : 'L');
			j = *++cp;
			i = *++cp;
			i -= 4;
			cp++;
			if (j > IPOPT_MINOFF) {
				for (;;) {
					__u32 address;
					memcpy(&address, cp, 4);
					cp += 4;
					if (address == 0)
						wfping_printf("\t0.0.0.0");
					else
						wfping_printf("\t%s", wfp_pr_addr(pwfp, address));
					j -= 4;
					wfping_putchar('\n');
					if (j <= IPOPT_MINOFF)
						break;
				}
			}
			break;
		case IPOPT_RR:
			j = *++cp;		/* get length */
			i = *++cp;		/* and pointer */
			if (i > j)
				i = j;
			i -= IPOPT_MINOFF;
			if (i <= 0)
				break;
			if (i == pwfp->old_rrlen
			    && !strncmp((char *)cp, pwfp->old_rr, i)
			    && !(pwfp->options & F_FLOOD)) {
				wfping_printf("\t(same route)");
				i = ((i + 3) / 4) * 4;
				cp += i;
				break;
			}
			pwfp->old_rrlen = i;
			memcpy(pwfp->old_rr, (char *)cp, i);
			wfping_printf("\nRR: ");
			cp++;
			for (;;) {
				__u32 address;
				memcpy(&address, cp, 4);
				cp += 4;
				if (address == 0)
					wfping_printf("\t0.0.0.0");
				else
					wfping_printf("\t%s", wfp_pr_addr(pwfp, address));
				i -= 4;
				wfping_putchar('\n');
				if (i <= 0)
					break;
			}
			break;
		case IPOPT_TS:
		{
			int stdtime = 0, nonstdtime = 0;
			__u8 flags;
			j = *++cp;		/* get length */
			i = *++cp;		/* and pointer */
			if (i > j)
				i = j;
			i -= 5;
			if (i <= 0)
				break;
			flags = *++cp;
			wfping_printf("\nTS: ");
			cp++;
			for (;;) {
				long l;

				if ((flags&0xF) != IPOPT_TS_TSONLY) {
					__u32 address;
					memcpy(&address, cp, 4);
					cp += 4;
					if (address == 0)
						wfping_printf("\t0.0.0.0");
					else
						wfping_printf("\t%s", wfp_pr_addr(pwfp, address));
					i -= 4;
					if (i <= 0)
						break;
				}
				l = *cp++;
				l = (l<<8) + *cp++;
				l = (l<<8) + *cp++;
				l = (l<<8) + *cp++;

				if  (l & 0x80000000) {
					if (nonstdtime==0)
						wfping_printf("\t%ld absolute not-standard", l&0x7fffffff);
					else
						wfping_printf("\t%ld not-standard", (l&0x7fffffff) - nonstdtime);
					nonstdtime = l&0x7fffffff;
				} else {
					if (stdtime==0)
						wfping_printf("\t%ld absolute", l);
					else
						wfping_printf("\t%ld", l - stdtime);
					stdtime = l;
				}
				i -= 4;
				wfping_putchar('\n');
				if (i <= 0)
					break;
			}
			if (flags>>4)
				wfping_printf("Unrecorded hops: %d\n", flags>>4);
			break;
		}
		default:
			wfping_printf("\nunknown option %x", *cp);
			break;
		}
		totlen -= optlen;
		optptr += optlen;
	}
}

static void pr_iph(wfping_t *pwfp, struct iphdr *ip)
{
	int hlen;
	u_char *cp;

	hlen = ip->ihl << 2;
	cp = (u_char *)ip + 20;		/* point to options */

	wfping_printf("Vr HL TOS  Len   ID Flg  off TTL Pro  cks      Src      Dst Data\n");
	wfping_printf(" %1x  %1x  %02x %04x %04x",
	       ip->version, ip->ihl, ip->tos, ip->tot_len, ip->id);
	wfping_printf("   %1x %04x", ((ip->frag_off) & 0xe000) >> 13,
	       (ip->frag_off) & 0x1fff);
	wfping_printf("  %02x  %02x %04x", ip->ttl, ip->protocol, ip->check);
	wfping_printf(" %s ", inet_ntoa(*(struct in_addr *)&ip->saddr));
	wfping_printf(" %s ", inet_ntoa(*(struct in_addr *)&ip->daddr));
	wfping_printf("\n");
	pr_options(pwfp, cp, hlen);
}

static void pr_icmph(wfping_t *pwfp, __u8 type, __u8 code, __u32 info, struct icmphdr *icp)
{
	switch(type) {
	case ICMP_ECHOREPLY:
		wfping_printf("Echo Reply\n");
		/* XXX ID + Seq + Data */
		break;
	case ICMP_DEST_UNREACH:
		switch(code) {
		case ICMP_NET_UNREACH:
			wfping_printf("Destination Net Unreachable\n");
			break;
		case ICMP_HOST_UNREACH:
			wfping_printf("Destination Host Unreachable\n");
			break;
		case ICMP_PROT_UNREACH:
			wfping_printf("Destination Protocol Unreachable\n");
			break;
		case ICMP_PORT_UNREACH:
			wfping_printf("Destination Port Unreachable\n");
			break;
		case ICMP_FRAG_NEEDED:
			wfping_printf("Frag needed and DF set (mtu = %u)\n", info);
			break;
		case ICMP_SR_FAILED:
			wfping_printf("Source Route Failed\n");
			break;
		case ICMP_PKT_FILTERED:
			wfping_printf("Packet filtered\n");
			break;
		default:
			wfping_printf("Dest Unreachable, Bad Code: %d\n", code);
			break;
		}
		if (icp && (pwfp->options & F_VERBOSE))
			pr_iph(pwfp, (struct iphdr*)(icp + 1));
		break;
	case ICMP_SOURCE_QUENCH:
		wfping_printf("Source Quench\n");
		if (icp && (pwfp->options & F_VERBOSE))
			pr_iph(pwfp, (struct iphdr*)(icp + 1));
		break;
	case ICMP_REDIRECT:
		switch(code) {
		case ICMP_REDIR_NET:
			wfping_printf("Redirect Network");
			break;
		case ICMP_REDIR_HOST:
			wfping_printf("Redirect Host");
			break;
		case ICMP_REDIR_NETTOS:
			wfping_printf("Redirect Type of Service and Network");
			break;
		case ICMP_REDIR_HOSTTOS:
			wfping_printf("Redirect Type of Service and Host");
			break;
		default:
			wfping_printf("Redirect, Bad Code: %d", code);
			break;
		}
		if (icp)
			wfping_printf("(New nexthop: %s)\n", wfp_pr_addr(pwfp, icp->un.gateway));
		if (icp && (pwfp->options & F_VERBOSE))
			pr_iph(pwfp, (struct iphdr*)(icp + 1));
		break;
	case ICMP_ECHO:
		wfping_printf("Echo Request\n");
		/* XXX ID + Seq + Data */
		break;
	case ICMP_TIME_EXCEEDED:
		switch(code) {
		case ICMP_EXC_TTL:
			wfping_printf("Time to live exceeded\n");
			break;
		case ICMP_EXC_FRAGTIME:
			wfping_printf("Frag reassembly time exceeded\n");
			break;
		default:
			wfping_printf("Time exceeded, Bad Code: %d\n", code);
			break;
		}
		if (icp && (pwfp->options & F_VERBOSE))
			pr_iph(pwfp, (struct iphdr*)(icp + 1));
		break;
	case ICMP_PARAMETERPROB:
		wfping_printf("Parameter problem: pointer = %u\n", icp ? (ntohl(icp->un.gateway)>>24) : info);
		if (icp && (pwfp->options & F_VERBOSE))
			pr_iph(pwfp, (struct iphdr*)(icp + 1));
		break;
	case ICMP_TIMESTAMP:
		wfping_printf("Timestamp\n");
		/* XXX ID + Seq + 3 timestamps */
		break;
	case ICMP_TIMESTAMPREPLY:
		wfping_printf("Timestamp Reply\n");
		/* XXX ID + Seq + 3 timestamps */
		break;
	case ICMP_INFO_REQUEST:
		wfping_printf("Information Request\n");
		/* XXX ID + Seq */
		break;
	case ICMP_INFO_REPLY:
		wfping_printf("Information Reply\n");
		/* XXX ID + Seq */
		break;
#ifdef ICMP_MASKREQ
	case ICMP_MASKREQ:
		wfping_printf("Address Mask Request\n");
		break;
#endif
#ifdef ICMP_MASKREPLY
	case ICMP_MASKREPLY:
		wfping_printf("Address Mask Reply\n");
		break;
#endif
	default:
		wfping_printf("Bad ICMP type: %d\n", type);
	}
}

static int send_probe(wfping_t *pwfp)
{
	struct icmphdr *icp;
	int cc;
	int i;

	icp = (struct icmphdr *)pwfp->outpack;
	icp->type = ICMP_ECHO;
	icp->code = 0;
	icp->checksum = 0;
	icp->un.echo.sequence = htons(pwfp->ntransmitted+1);
	//icp->un.echo.id = pwfp->ident;

	CLR(pwfp, (pwfp->ntransmitted+1) % MAX_DUP_CHK);

	if (pwfp->timing) {
		if (pwfp->options&F_LATENCY) {
			struct timeval tmp_tv;
			gettimeofday(&tmp_tv, NULL);
			/* egcs is crap or glibc is crap, but memcpy
			   does not copy anything, if len is constant! */
			memcpy(icp+1, &tmp_tv, sizeof(struct timeval));
		} else {
			memset(icp+1, 0, sizeof(struct timeval));
		}
	}

	cc = pwfp->datalen + 8 + sizeof(struct icmphdr);

	/* compute ICMP checksum here */
	//icp->checksum = in_cksum((u_short *)icp, cc, 0);

	if (pwfp->timing && !(pwfp->options&F_LATENCY)) {
		struct timeval tmp_tv;
		gettimeofday(&tmp_tv, NULL);
		/* egcs is crap or glibc is crap, but memcpy
		   does not copy anything, if len is constant! */
		memcpy(icp+1, &tmp_tv, sizeof(struct timeval));
		//icp->checksum = in_cksum((u_short *)(icp+1), sizeof(struct timeval), ~icp->checksum);
	}

	do {
		i = sendto(pwfp->icmp_sock, pwfp->outpack, cc, 0, (struct sockaddr *)&(pwfp->whereto), sizeof(struct sockaddr_in) );
	} while (0);

	return (cc == i ? 0 : i);
}

static int receive_error_msg(wfping_t *pwfp)
{
    int res;
    char cbuf[512];
    struct iovec  iov;
    struct msghdr msg;
    struct cmsghdr *cmsg;
    struct sock_extended_err *e;
    struct icmphdr icmph;
    struct sockaddr_in target;
    int net_errors = 0;
    int local_errors = 0;
    int saved_errno = errno;

    iov.iov_base = &icmph;
    iov.iov_len = sizeof(icmph);
    msg.msg_name = (void*)&target;
    msg.msg_namelen = sizeof(target);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_flags = 0;
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);

    res = recvmsg(pwfp->icmp_sock, &msg, MSG_ERRQUEUE|MSG_DONTWAIT);
    if (res < 0)
        goto out;

    e = NULL;
    for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
	if (cmsg->cmsg_level == SOL_IP) {
	    if (cmsg->cmsg_type == IP_RECVERR)
		e = (struct sock_extended_err *)CMSG_DATA(cmsg);
	} 
    }
    if (e == NULL)
	abort();

    if (e->ee_origin == SO_EE_ORIGIN_LOCAL) {
	local_errors++;
	if (pwfp->options & F_QUIET)
	    goto out;
	if (pwfp->options & F_FLOOD)
	    write(STDOUT_FILENO, "E", 1);
	else if (e->ee_errno != EMSGSIZE)
	    WFPING_ERROR("wfping: local error: %s\n", strerror(e->ee_errno));
	else
	    WFPING_ERROR("wfping: local error: Message too long, mtu=%u\n", e->ee_info);
	pwfp->nerrors++;
	} else if (e->ee_origin == SO_EE_ORIGIN_ICMP) {
	    struct sockaddr_in *sin = (struct sockaddr_in*)(e+1);

	    if (res < sizeof(icmph) || target.sin_addr.s_addr != pwfp->whereto.sin_addr.s_addr ||
			icmph.type != ICMP_ECHO) {
			/* Not our error, not an error at all. Clear. */
		saved_errno = 0;
		goto out;
	    }

	    acknowledge(pwfp, ntohs(icmph.un.echo.sequence));

		net_errors++;
		pwfp->nerrors++;
		if (pwfp->options & F_QUIET)
		    goto out;
		if (pwfp->options & F_FLOOD) {
		    write(STDOUT_FILENO, "\bE", 2);
		} else {
		    print_timestamp(pwfp);
		    wfping_printf("From %s icmp_seq=%u ", wfp_pr_addr(pwfp, sin->sin_addr.s_addr), ntohs(icmph.un.echo.sequence));
		    pr_icmph(pwfp, e->ee_type, e->ee_code, e->ee_info, NULL);
		    wfping_fflush(stdout);
		}
	}

out:
	errno = saved_errno;
	return net_errors ? : -local_errors;
}

/*
 * pinger --
 * 	Compose and transmit an ICMP ECHO REQUEST packet.  The IP packet
 * will be added on by the kernel.  The ID field is our UNIX process ID,
 * and the sequence number is an ascending integer.  The first 8 bytes
 * of the data portion are used to hold a UNIX "timeval" struct in VAX
 * byte-order, to compute the round-trip time.
 */
static int wfpinger(wfping_t *pwfp)
{
	int i;

	/* Have we already sent enough? If we have, return an arbitrary positive value. */
	if (pwfp->exiting || (pwfp->npackets && pwfp->ntransmitted >= pwfp->npackets && !pwfp->deadline))
		return 1000;

	/* Check that packets < rate*time + preload */
	if (pwfp->cur_time.tv_sec == 0) {
		gettimeofday(&pwfp->cur_time, NULL);
		pwfp->tokens = 0;
	} else {
		long ntokens;
		struct timeval tv;

		gettimeofday(&tv, NULL);
		ntokens = (tv.tv_sec - pwfp->cur_time.tv_sec)*1000 +
			(tv.tv_usec-pwfp->cur_time.tv_usec)/1000;
		if (!pwfp->interval_ms) {
			/* Case of unlimited flood is special;
			 * if we see no reply, they are limited to 100pps */
			if (ntokens < MININTERVAL && in_flight(pwfp) >= 1)
				return MININTERVAL-ntokens;
		}
		ntokens += pwfp->tokens;
		if (ntokens > pwfp->interval_ms)
			ntokens = pwfp->interval_ms;
		if (ntokens < pwfp->interval_ms)
			return pwfp->interval_ms - ntokens;

		pwfp->cur_time = tv;
		pwfp->tokens = ntokens - pwfp->interval_ms;
	}

resend:
	i = send_probe(pwfp);

	if (i == 0) {
		pwfp->oom_count = 0;
		advance_ntransmitted(pwfp);
		return pwfp->interval_ms - pwfp->tokens;
	}

	/* And handle various errors... */
	if (i > 0) {
		/* Apparently, it is some fatal bug. */
		pwfp->exiting = 1;
		return 1000;
	} else if (errno == ENOBUFS || errno == ENOMEM) {
		int nores_interval;

		/* Device queue overflow or OOM. Packet is not sent. */
		pwfp->tokens = 0;
		/* Slowdown. This works only in adaptive mode (option -A) */
		pwfp->rtt_addend += (pwfp->rtt < 8*50000 ? pwfp->rtt/8 : 50000);
		if (pwfp->options&F_ADAPTIVE)
			update_interval(pwfp);
		nores_interval = SCHINT(pwfp->interval_ms/2);
		if (nores_interval > 500)
			nores_interval = 500;
		pwfp->oom_count++;
		if (pwfp->oom_count*nores_interval < (MAXWAIT*1000))
			return nores_interval;
		i = 0;
		/* Fall to hard error. It is to avoid complete deadlock
		 * on stuck output device even when dealine was not requested.
		 * Expected timings are screwed up in any case, but we will
		 * exit some day. :-) */
	} else if (errno == EAGAIN) {
		/* Socket buffer is full. */
		pwfp->tokens += pwfp->interval_ms;
		return MININTERVAL;
	} else {
		if ((i=receive_error_msg(pwfp)) > 0) {
			/* An ICMP error arrived. */
			pwfp->tokens += pwfp->interval_ms;
			return MININTERVAL;
		}
		/* Compatibility with old linuces. */
		if (i == 0 && errno == EINVAL) {
			errno = 0;
		}
		if (!errno)
			goto resend;
	}

	/* Hard local error. Pretend we sent packet. */
	advance_ntransmitted(pwfp);

	if (i == 0 && !(pwfp->options & F_QUIET)) {
		if (pwfp->options & F_FLOOD)
			write(STDOUT_FILENO, "E", 1);
		else
			WFPING_PERROR("wfping: sendmsg");
	}
	pwfp->tokens = 0;
	return SCHINT(pwfp->interval_ms);
}

static int gather_statistics(wfping_t *pwfp, __u8 *icmph, int icmplen,
		      int cc, __u16 seq, int hops,
		      int csfailed, struct timeval *tv, char *from,
		      void (*pr_reply)(__u8 *icmph, int cc))
{
	int dupflag = 0;
	long triptime = 0;
	__u8 *ptr = icmph + icmplen;

	++pwfp->nreceived;
	if (!csfailed)
		acknowledge(pwfp, seq);

	if (pwfp->timing && cc >= 8+sizeof(struct timeval)) {
		struct timeval tmp_tv;
		memcpy(&tmp_tv, ptr, sizeof(tmp_tv));

restamp:
		wfp_tvsub(tv, &tmp_tv);
		triptime = tv->tv_sec * 1000000 + tv->tv_usec;
		if (triptime < 0) {
			WFPING_ERROR("Warning: time of day goes back (%ldus), taking countermeasures.\n", triptime);
			triptime = 0;
			if (!(pwfp->options & F_LATENCY)) {
				gettimeofday(tv, NULL);
				pwfp->options |= F_LATENCY;
				goto restamp;
			}
		}
		if (!csfailed) {
			pwfp->tsum += triptime;
			pwfp->tsum2 += (long long)triptime * (long long)triptime;
			if (triptime < pwfp->tmin)
				pwfp->tmin = triptime;
			if (triptime > pwfp->tmax)
				pwfp->tmax = triptime;
			if (!pwfp->rtt)
				pwfp->rtt = triptime*8;
			else
				pwfp->rtt += triptime-pwfp->rtt/8;
			if (pwfp->options&F_ADAPTIVE)
				update_interval(pwfp);
		}
	}

	if (csfailed) {
		++pwfp->nchecksum;
		--pwfp->nreceived;
	} else if (TST(pwfp, seq % MAX_DUP_CHK)) {
		++pwfp->nrepeats;
		--pwfp->nreceived;
		dupflag = 1;
	} else {
		SET(pwfp, seq % MAX_DUP_CHK);
		dupflag = 0;
	}

	if (pwfp->options & F_QUIET)
		return 1;

	if (pwfp->options & F_FLOOD) {
		if (!csfailed)
			write(STDOUT_FILENO, "\b \b", 3);
		else
			write(STDOUT_FILENO, "\bC", 1);
	} else {
		int i;
		__u8 *cp, *dp;

		print_timestamp(pwfp);
		wfping_printf("%d bytes from %s:", cc, from);

		if (pr_reply)
			pr_reply(icmph, cc);

		if (hops >= 0)
			wfping_printf(" ttl=%d", hops);

		if (cc < pwfp->datalen+8) {
			wfping_printf(" (truncated)\n");
			return 1;
		}
		if (pwfp->timing) {
			if (triptime >= 100000)
				wfping_printf(" time=%ld ms", triptime/1000);
			else if (triptime >= 10000)
				wfping_printf(" time=%ld.%01ld ms", triptime/1000,
				       (triptime%1000)/100);
			else if (triptime >= 1000)
				wfping_printf(" time=%ld.%02ld ms", triptime/1000,
				       (triptime%1000)/10);
			else
				wfping_printf(" time=%ld.%03ld ms", triptime/1000,
				       triptime%1000);
		}
		if (dupflag)
			wfping_printf(" (DUP!)");
		if (csfailed)
			wfping_printf(" (BAD CHECKSUM!)");

		/* check the data */
		cp = ((u_char*)ptr) + sizeof(struct timeval);
		dp = &pwfp->outpack[8 + sizeof(struct timeval)];
		for (i = sizeof(struct timeval); i < pwfp->datalen; ++i, ++cp, ++dp) {
			if (*cp != *dp) {
				wfping_printf("\nwrong data byte #%d should be 0x%x but was 0x%x",
				       i, *dp, *cp);
				cp = (u_char*)ptr + sizeof(struct timeval);
				for (i = sizeof(struct timeval); i < pwfp->datalen; ++i, ++cp) {
					if ((i % 32) == sizeof(struct timeval))
						wfping_printf("\n#%d\t", i);
					wfping_printf("%x ", *cp);
				}
				break;
			}
		}
	}
	return 0;
}

static void pr_echo_reply(__u8 *_icp, int len)
{
	struct icmphdr *icp = (struct icmphdr *)_icp;
	wfping_printf(" icmp_req=%u", ntohs(icp->un.echo.sequence));
}

static unsigned short in_cksum(const unsigned short *addr, register int len, unsigned short csum)
{
	register int nleft = len;
	const unsigned short *w = addr;
	register unsigned short answer;
	register int sum = csum;

	/*
	 *  Our algorithm is simple, using a 32 bit accumulator (sum),
	 *  we add sequential 16 bit words to it, and at the end, fold
	 *  back all the carry bits from the top 16 bits into the lower
	 *  16 bits.
	 */
	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1)
		sum += htons(*(u_char *)w << 8);

	/*
	 * add back carry outs from top 16 bits to low 16 bits
	 */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return (answer);
}

static int parse_reply(wfping_t *pwfp, struct msghdr *msg, int cc, void *addr, struct timeval *tv)
{
	struct sockaddr_in *from = addr;
	__u8 *buf = msg->msg_iov->iov_base;
	struct icmphdr *icp;
	int csfailed;
	int hlen = 0;

	/* Now the ICMP part */
	cc -= hlen;
	icp = (struct icmphdr *)(buf + hlen);
	csfailed = in_cksum((u_short *)icp, cc, 0);

	if (icp->type == ICMP_ECHOREPLY) {
		//printf("thread %x recv ICMP_ECHOREPLY  id=%d \n", (unsigned int)pthread_self(), icp->un.echo.id);
		if (gather_statistics(pwfp, (__u8*)icp, sizeof(*icp), cc,
				      ntohs(icp->un.echo.sequence),
				      0, 0, tv, wfp_pr_addr(pwfp, from->sin_addr.s_addr),
				      pr_echo_reply))
			return 0;
	} else {
		/* We fall here when a redirect or source quench arrived.
		 * Also this branch processes icmp errors, when IP_RECVERR
		 * is broken. */

		switch (icp->type) {
		case ICMP_ECHO:
			/* MUST NOT */
		//printf("thread %x recv ICMP_ECHO \n", (unsigned int)pthread_self());
			return 1;
		case ICMP_SOURCE_QUENCH:
		case ICMP_REDIRECT:
		case ICMP_DEST_UNREACH:
		case ICMP_TIME_EXCEEDED:
		case ICMP_PARAMETERPROB:
			{
				struct iphdr * iph = (struct  iphdr *)(&icp[1]);
				struct icmphdr *icp1 = (struct icmphdr*)((unsigned char *)iph + iph->ihl*4);
				int error_pkt;
				if (cc < 8+sizeof(struct iphdr)+8 ||
				    cc < 8+iph->ihl*4+8)
					return 1;
				if (icp1->type != ICMP_ECHO ||
				    iph->daddr != pwfp->whereto.sin_addr.s_addr)
					return 1;
				error_pkt = (icp->type != ICMP_REDIRECT &&
					     icp->type != ICMP_SOURCE_QUENCH);
				if (error_pkt) {
					acknowledge(pwfp, ntohs(icp1->un.echo.sequence));
					/* Sigh, IP_RECVERR for raw socket
					 * was broken until 2.4.9. So, we ignore
					 * the first error and warn on the second.
					 */
					if (pwfp->once++ == 1)
						WFPING_ERROR("\rWARNING: kernel is not very fresh, upgrade is recommended.\n");
					if (pwfp->once == 1)
						return 0;
				}
				pwfp->nerrors+=error_pkt;
				if (pwfp->options&F_QUIET)
					return !error_pkt;
				if (pwfp->options & F_FLOOD) {
					if (error_pkt)
						write(STDOUT_FILENO, "\bE", 2);
					return !error_pkt;
				}
				print_timestamp(pwfp);
				wfping_printf("From %s: icmp_seq=%u ",
				       wfp_pr_addr(pwfp, from->sin_addr.s_addr),
				       ntohs(icp1->un.echo.sequence));
				if (csfailed)
					wfping_printf("(BAD CHECKSUM)");
				pr_icmph(pwfp, icp->type, icp->code, ntohl(icp->un.gateway), icp);
				return !error_pkt;
			}
		default:
			/* MUST NOT */
			break;
		}
		if ((pwfp->options & F_FLOOD) && !(pwfp->options & (F_VERBOSE|F_QUIET))) {
			if (!csfailed)
				write(STDOUT_FILENO, "!E", 2);
			else
				write(STDOUT_FILENO, "!EC", 3);
			return 0;
		}
		if (!(pwfp->options & F_VERBOSE)
		#ifndef LIB_WFPING_FOR_THREAD
			|| pwfp->uid
		#endif
			)
			return 0;
		if (pwfp->options & F_PTIMEOFDAY) {
			struct timeval recv_time;
			gettimeofday(&recv_time, NULL);
			wfping_printf("%lu.%06lu ", (unsigned long)recv_time.tv_sec, (unsigned long)recv_time.tv_usec);
		}
		wfping_printf("From %s: ", wfp_pr_addr(pwfp, from->sin_addr.s_addr));
		if (csfailed) {
			wfping_printf("(BAD CHECKSUM)\n");
			return 0;
		}
		pr_icmph(pwfp, icp->type, icp->code, ntohl(icp->un.gateway), icp);
		return 0;
	}

	if (!(pwfp->options & F_FLOOD)) {
		pr_options(pwfp, buf + sizeof(struct iphdr), hlen);

		if (pwfp->options & F_AUDIBLE)
			wfping_putchar('\a');
		wfping_putchar('\n');
		wfping_fflush(stdout);
	} else {
		wfping_putchar('\a');
		wfping_fflush(stdout);
	}
	return 0;
}

static long llsqrt(long long a)
{
	long long prev = ~((long long)1 << 63);
	long long x = a;

	if (x > 0) {
		while (x < prev) {
			prev = x;
			x = (x+(a/x))/2;
		}
	}

	return (long)x;
}

static int wfping_finish(wfping_t *pwfp)
{
	struct timeval tv = pwfp->cur_time;
	char *comma = "";
	int exit_code = 0;

	wfp_tvsub(&tv, &pwfp->start_time);

	putchar('\n');
	fflush(stdout);
	printf("--- %s ping statistics --- %ld ---\n", pwfp->ip_name, pwfp->recv_pkt);
	printf("%ld packets transmitted, ", pwfp->ntransmitted);
	printf("%ld received", pwfp->nreceived);
	if (pwfp->nrepeats)
		printf(", +%ld duplicates", pwfp->nrepeats);
	if (pwfp->nchecksum)
		printf(", +%ld corrupted", pwfp->nchecksum);
	if (pwfp->nerrors)
		printf(", +%ld errors", pwfp->nerrors);
	if (pwfp->ntransmitted) {
		printf(", %d%% packet loss",
		       (int) ((((long long)(pwfp->ntransmitted - pwfp->nreceived)) * 100) /
			      pwfp->ntransmitted));
		printf(", time %ldms", 1000*tv.tv_sec+tv.tv_usec/1000);
	}
	putchar('\n');

	if (pwfp->nreceived && pwfp->timing) {
		long tmdev;

		pwfp->tsum /= pwfp->nreceived + pwfp->nrepeats;
		pwfp->tsum2 /= pwfp->nreceived + pwfp->nrepeats;
		tmdev = llsqrt(pwfp->tsum2 - pwfp->tsum * pwfp->tsum);

		printf("rtt min/avg/max/mdev = %ld.%03ld/%lu.%03ld/%ld.%03ld/%ld.%03ld ms",
		       (long)pwfp->tmin/1000, (long)pwfp->tmin%1000,
		       (unsigned long)(pwfp->tsum/1000), (long)(pwfp->tsum%1000),
		       (long)pwfp->tmax/1000, (long)pwfp->tmax%1000,
		       (long)tmdev/1000, (long)tmdev%1000
		       );
		comma = ", ";
	}
	if (pwfp->ntransmitted > 1 && (!pwfp->interval_ms || (pwfp->options&(F_FLOOD|F_ADAPTIVE)))) {
		int ipg = (1000000*(long long)tv.tv_sec+tv.tv_usec)/(pwfp->ntransmitted-1);
		printf("%sipg/ewma %d.%03d/%d.%03d ms",
		       comma, ipg/1000, ipg%1000, pwfp->rtt/8000, (pwfp->rtt/8)%1000);
	}
	putchar('\n');

	exit_code = !pwfp->nreceived || (pwfp->deadline && pwfp->nreceived < pwfp->npackets);
	return exit_code;
}


int wfping_main(wfping_t *set_wfp, int argc, char **argv)
{
	int ret = 0, next = 0, polling = 0, cc = 0, packlen = 0;
	char addrbuf[128];
	char ans_data[4096];
	struct iovec iov;
	struct msghdr msg;
	struct cmsghdr *c;
	wfping_t *pwfp = NULL;

#ifdef LIB_WFPING
	if(set_wfp)
		pwfp = set_wfp;
	else{
		pwfp = (wfping_t *)malloc(sizeof(wfping_t));
		if(!pwfp){
			WFPING_PERROR("wfping: malloc");
			return 1;
		}
	}
#else
	pwfp = &g_wfp;
#endif

	default_set_wfping(pwfp);
#ifndef LIB_WFPING_FOR_THREAD
	pwfp->uid = getuid();
	if (setuid(pwfp->uid)){
		WFPING_PERROR("wfping: setuid");
		ret = -1;
		goto END;
	}
#endif
	pwfp->icmp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
	if(pwfp->icmp_sock < 0){
		WFPING_PERROR("wfping: icmp open socket");
		ret = 2;
		goto END;
	}
		
	if(init_wfping_by_arg(pwfp, argc, argv) < 0){
		ret = 2;
		goto END;
	}

	if(check_and_set_wfping(pwfp) < 0){
		ret = 2;
		goto END;
	}

	printf("PING %s (%s) ", pwfp->target_host, inet_ntoa(pwfp->whereto.sin_addr));
	if (pwfp->device || (pwfp->options & F_STRICTSOURCE))
		printf("from %s %s: ", inet_ntoa(pwfp->source.sin_addr), pwfp->device ?: "");
	printf("%d(%d) bytes of data.\n", pwfp->datalen, pwfp->datalen+8+pwfp->optlen+20);

	if(setup_icmp_sock(pwfp) < 0){
		ret = 2;
		goto END;
	}

	packlen = pwfp->datalen + MAXIPLEN + MAXICMPLEN;
	iov.iov_base = (char *)pwfp->packet;
	for (;;) 
	{
		/* Check exit conditions. */
		if (pwfp->exiting)
			break;
		if (pwfp->npackets && pwfp->nreceived + pwfp->nerrors >= pwfp->npackets)
			break;
		if (pwfp->deadline && (pwfp->nerrors || is_deadline(pwfp)))
			break;

		do {
			next = wfpinger(pwfp);
		} while (next <= 0);
		/* "next" is time to send next probe, if positive.
		 * If next<=0 send now or as soon as possible. */

		/* Technical part. Looks wicked. Could be dropped,
		 * if everyone used the newest kernel. :-)
		 * Its purpose is:
		 * 1. Provide intervals less than resolution of scheduler.
		 *    Solution: spinning.
		 * 2. Avoid use of poll(), when recvmsg() can provide
		 *    timed waiting (SO_RCVTIMEO). */
		polling = 0;
		if ((pwfp->options & (F_ADAPTIVE|F_FLOOD_POLL)) || next<SCHINT(pwfp->interval_ms)) {
			int recv_expected = in_flight(pwfp);

			/* If we are here, recvmsg() is unable to wait for
			 * required timeout. */
			if (1000*next <= 1000000/(int)HZ) {
				/* Very short timeout... So, if we wait for
				 * something, we sleep for MININTERVAL.
				 * Otherwise, spin! */
				if (recv_expected) {
					next = MININTERVAL;
				} else {
					next = 0;
					/* When spinning, no reasons to poll.
					 * Use nonblocking recvmsg() instead. */
					polling = MSG_DONTWAIT;
					/* But yield yet. */
					sched_yield();
				}
			}

			if (!polling &&
			    ((pwfp->options & (F_ADAPTIVE|F_FLOOD_POLL)) || pwfp->interval_ms)) {
				struct pollfd pset;
				pset.fd = pwfp->icmp_sock;
				pset.events = POLLIN|POLLERR;
				pset.revents = 0;
				if (poll(&pset, 1, next) < 1 ||
				    !(pset.revents&(POLLIN|POLLERR)))
					continue;
				polling = MSG_DONTWAIT;
			}
		}

		for (;;) {
			struct timeval *recv_timep = NULL;
			struct timeval recv_time;

			iov.iov_len = packlen;
			memset(&msg, 0, sizeof(msg));
			msg.msg_name = addrbuf;
			msg.msg_namelen = sizeof(addrbuf);
			msg.msg_iov = &iov;
			msg.msg_iovlen = 1;
			msg.msg_control = ans_data;
			msg.msg_controllen = sizeof(ans_data);

			cc = recvmsg(pwfp->icmp_sock, &msg, polling);
			polling = MSG_DONTWAIT;

			if (cc < 0) {
				if (errno == EAGAIN || errno == EINTR)
					break;
				if (!receive_error_msg(pwfp)) {
					if (errno) {
						WFPING_PERROR("ping: recvmsg");
						break;
					}
				}
			} 
			else {
				++pwfp->recv_pkt;
#ifdef SO_TIMESTAMP
				for (c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
					if (c->cmsg_level != SOL_SOCKET ||
					    c->cmsg_type != SO_TIMESTAMP)
						continue;
					if (c->cmsg_len < CMSG_LEN(sizeof(struct timeval)))
						continue;
					recv_timep = (struct timeval*)CMSG_DATA(c);
				}
#endif

				if ((pwfp->options&F_LATENCY) || recv_timep == NULL) {
					if ((pwfp->options&F_LATENCY) ||
					    ioctl(pwfp->icmp_sock, SIOCGSTAMP, &recv_time))
						gettimeofday(&recv_time, NULL);
					recv_timep = &recv_time;
				}

				parse_reply(pwfp, &msg, cc, addrbuf, recv_timep);
			}

			/* If nothing is in flight, "break" returns us to pinger. */
			if (in_flight(pwfp) == 0)
				break;

			/* Otherwise, try to recvmsg() again. recvmsg()
			 * is nonblocking after the first iteration, so that
			 * if nothing is queued, it will receive EAGAIN
			 * and return to pinger. */
		}
	}
	ret = wfping_finish(pwfp);

END:

	if(pwfp->icmp_sock >= 0)
		close(pwfp->icmp_sock);
	if(pwfp->packet){
		free(pwfp->packet);
		pwfp->packet = NULL;
	}

#ifdef LIB_WFPING
#ifdef LIB_WFPING_FOR_THREAD
	if(pwfp->tmp_buf){
		free(pwfp->tmp_buf);
		pwfp->tmp_buf = NULL;
	}
#endif
	if(!set_wfp)
		free(pwfp);
#endif

	return ret;
}

#ifndef LIB_WFPING
int main(int argc, char **argv)
{
	return wfping_main(NULL, argc, argv);
}
#endif

