#ifndef WFPING_H_
#define WFPING_H_

#include <net/if.h>

#include <arpa/inet.h>
#include <arpa/inet.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <sys/signal.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/param.h>

#include <linux/sockios.h>
#include <linux/types.h>
#include <linux/errqueue.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

// ------------------ config

// ------------------ config --- end


#ifndef LIB_WFPING
#undef LIB_WFPING_FOR_THREAD
#endif

#define	MAXIPLEN	60
#define	MAXICMPLEN	76
#define	NROUTES		9		/* number of record route slots */
#define TOS_MAX		255		/* 8-bit TOS field */
#define	MAX_DUP_CHK	0x10000


#define	DEFDATALEN	(64 - 8)	/* default data length */

#define	MAXWAIT		10		/* max seconds to wait for response */
#define MININTERVAL	1		/* Minimal interpacket gap */
#define MINUSERINTERVAL	2	/* Minimal allowed interval for non-root */

#define SCHINT(a)	(((a) <= MININTERVAL) ? MININTERVAL : (a))

#define	A(pwfp, bit)		pwfp->rcvd_tbl[(bit)>>3]	/* identify byte in array */
#define	B(bit)		(1 << ((bit) & 0x07))	/* identify bit in byte */
#define	SET(pwfp, bit)	(A(pwfp, bit) |= B(bit))
#define	CLR(pwfp, bit)	(A(pwfp, bit) &= (~B(bit)))
#define	TST(pwfp, bit)	(A(pwfp, bit) & B(bit))


#define	F_FLOOD		0x001
#define	F_INTERVAL	0x002
#define	F_NUMERIC	0x004
#define	F_PINGFILLED	0x008
#define	F_QUIET		0x010
#define	F_RROUTE	0x020
#define	F_SO_DEBUG	0x040
#define	F_SO_DONTROUTE	0x080
#define	F_VERBOSE	0x100
#define	F_TIMESTAMP	0x200
#define	F_FLOWINFO	0x200
#define	F_SOURCEROUTE	0x400
#define	F_TCLASS	0x400
#define	F_FLOOD_POLL	0x800
#define	F_LATENCY	0x1000
#define	F_AUDIBLE	0x2000
#define	F_ADAPTIVE	0x4000
#define	F_STRICTSOURCE	0x8000
#define F_NOLOOP	0x10000
#define F_TTL		0x20000
#define F_MARK		0x40000
#define F_PTIMEOFDAY	0x80000


#define WFPING_MAXPACKET 0x10000
#define WFPING_ROUTE_MAX_COUNT 10
typedef struct wfping_s{
#ifdef LIB_WFPING
	void *wfp_id; // used by caller
#endif
	int interval_ms; // interval between packets (msec)
	int sndbuf_size;
	int datalen;
	int settos;
	int broadcast_pings;
	int pmtudisc;
	int ts_type;
	int ttl;
	int mark;
	int deadline;
	long npackets; // number of packets to transmit
	char *device;
	char *target_host;

	int options;
	int timing;
	char ip_name[16];
	struct sockaddr_in whereto;
	struct sockaddr_in source;
	unsigned int route[WFPING_ROUTE_MAX_COUNT];
	int nroute;
	int icmp_sock;
	int icmp_req;
	int optlen;
	unsigned char *packet;
	unsigned char outpack[WFPING_MAXPACKET];
	int rtt;
	int rtt_addend;
	
	struct timeval start_time;
	struct timeval cur_time;
	long nreceived; // right packet
	long nrepeats; // number of duplicates
	long ntransmitted;
	long nchecksum; // replies with bad checksum
	long nerrors; // icmp errors
	unsigned short acked;
	long long tsum, tsum2;
	long tmin, tmax;
	long recv_pkt;	// all packet

	int old_rrlen;
	char old_rr[MAX_IPOPTLEN];
	int oom_count;
	int tokens;
	int once;
	char rcvd_tbl[MAX_DUP_CHK / 8];

	int exiting;
#ifdef LIB_WFPING_FOR_THREAD
	char *tmp_buf;
#else
	int uid;
#endif
}wfping_t;

#endif

