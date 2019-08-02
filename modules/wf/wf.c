#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

#include <linux/types.h>
#include <linux/timer.h>

#include <linux/netfilter.h>
#include <linux/if_ether.h>

#include <net/net_namespace.h> // for init_net
#include <linux/seq_file.h>
#include <linux/proc_fs.h>

#include "wf.h"

#include <net/netfilter/nf_conntrack_extend.h>


// -------------- api
//smp_processor_id
void ct_status_2_str(struct nf_conn *ct, char *str, int size)
{
	char ct_status[256] = {'\0'};

	if (test_bit(IPS_SEEN_REPLY_BIT, &ct->status))
		strcat(ct_status, " SEEN_REPLY");
	if (test_bit(IPS_ASSURED_BIT, &ct->status))
		strcat(ct_status, " ASSURED");
	if (test_bit(IPS_CONFIRMED_BIT, &ct->status))
		strcat(ct_status, " CONFIRMED");
	if (test_bit(IPS_DYING_BIT, &ct->status))
		strcat(ct_status, " DYING");
	if (test_bit(IPS_FIXED_TIMEOUT_BIT, &ct->status))
		strcat(ct_status, " FIXED_TIMEOUT");
	if (test_bit(IPS_TEMPLATE_BIT, &ct->status))
		strcat(ct_status, " TEMPLATE");
	if (test_bit(IPS_UNTRACKED_BIT, &ct->status))
		strcat(ct_status, " UNTRACKED");
	if(ct_status[0] == ' ')
		strncpy(str, &ct_status[1], size-1);
	else
		str[0] = '\0';
}

struct nf_conn *skb2ct(const struct sk_buff *skb, enum ip_conntrack_dir *ct_dir,enum ip_conntrack_info *pctinfo)
{
	struct nf_conn * ct = NULL;

	ct = nf_ct_get(skb, pctinfo);
	if(!ct){
		return NULL;
	}
	*ct_dir = *pctinfo >= IP_CT_IS_REPLY ? IP_CT_DIR_REPLY : IP_CT_DIR_ORIGINAL;

	return ct;
}


void netlink_skb_init(struct sk_buff *skb, u32 type, u32 seq, pid_t dst_pid, unsigned int payload_len)
{
	struct nlmsghdr * _nlh = NULL;

	WF_ASSERT_POINTER(skb);

	_nlh = (struct nlmsghdr *)skb->data;
	_nlh->nlmsg_type = type;
	_nlh->nlmsg_seq = seq;
	_nlh->nlmsg_len = NLMSG_SPACE(payload_len);

#if LINUX_VERSION_CODE == KERNEL_VERSION(2,6,12)
	NETLINK_CB(skb).groups = 0;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	NETLINK_CB(skb).portid = 0;
#else
	NETLINK_CB(skb).pid = 0;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,21)
#else
	NETLINK_CB(skb).dst_pid = dst_pid;
#endif

#ifdef NET_SKBUFF_DATA_USES_OFFSET
	skb->tail = NLMSG_SPACE(payload_len);
#else
	skb->tail = skb->head + NLMSG_SPACE(payload_len);
#endif

	skb->len = NLMSG_SPACE(payload_len);
}

struct sk_buff *netlink_alloc_skb_and_init(u32 type, u32 seq, pid_t dst_pid, unsigned int payload_len, gfp_t *priority)
{
	struct sk_buff *skb;
	gfp_t set_priority = in_atomic() ? GFP_ATOMIC :GFP_KERNEL;
	
	if(priority)
		set_priority = *priority;
	skb = alloc_skb(NLMSG_SPACE(payload_len), set_priority);
	if (!skb ){
		return NULL;
	}
	netlink_skb_init(skb, type, seq, dst_pid, payload_len);
	return skb;
}

int netlink_skb_push_data(struct nlmsghdr *nlh, int *offset, void *data, int len)
{
	WF_ASSERT_POINTER(nlh);
	WF_ASSERT_POINTER(data);

//	wfptk_debug("pdata=%p len=%d nlh->nlmsg_len=%d\n", data, len, nlh->nlmsg_len);
	if(len > (nlh->nlmsg_len - (*offset))){
	//	wfptk_debug("pdata=%p len=%d nlh->nlmsg_len=%d\n", data, len, nlh->nlmsg_len);
		return -1;
	}

	memcpy(NLMSG_DATA(nlh) + (*offset), data, len);
	(*offset) += len;

	return 0;
}

int netlink_skb_pop_data(struct nlmsghdr *nlh, int *offset, void *data, int len)
{
	WF_ASSERT_POINTER(nlh);
	WF_ASSERT_POINTER(data);

//	wfptk_debug("pdata=%p len=%d nlh->nlmsg_len=%d\n", data, len, nlh->nlmsg_len);
	if(len > (nlh->nlmsg_len - (*offset))){
//		wfptk_debug("pdata=%p len=%d nlh->nlmsg_len=%d\n", data, len, nlh->nlmsg_len);
		return -1;
	}
	memcpy(data, NLMSG_DATA(nlh) + (*offset),len);
	(*offset) += len;

	return 0;
}

int netlink_send_data(struct sock *nlsk, struct sk_buff *skb, void *data, int len)
{
	struct nlmsghdr *_nlh = NULL;
	int offset = 0;

	_nlh = (struct nlmsghdr *)skb ->data;
	if(netlink_skb_push_data(_nlh, &offset, data, len)){
		return -1;
	}
	return netlink_unicast(nlsk, skb, _nlh->nlmsg_pid, MSG_DONTWAIT);
}

int netlink_broadcast_data(struct sock *nlsk, struct sk_buff *skb, u32 dst_groups, void *data, int len)
{
	struct nlmsghdr *_nlh = NULL;
	int offset = 0;

	_nlh = (struct nlmsghdr *)skb ->data;
	if(netlink_skb_push_data(_nlh, &offset, data, len)){
		return -1;
	}
	return netlink_broadcast(nlsk, skb, 0, dst_groups, GFP_ATOMIC);
}

// -------------- api --- end

static struct timer_list broadcast_hello_timer;


unsigned int wf_after_conntrack_in(unsigned int hooknum,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
	struct sk_buff *skb,
#else
	struct sk_buff **pskb,
#endif
	const struct net_device *in, const struct net_device *out,
	int (*okfn)(struct sk_buff *))
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
#else
	struct sk_buff * skb = *pskb;
#endif
	struct nf_conn *ct;
	enum ip_conntrack_dir ct_dir = IP_CT_DIR_MAX;
	enum ip_conntrack_info pctinfo;

	char strbuf[256] = {'\0'};

	if(!skb)
		return NF_ACCEPT;

	ct = skb2ct(skb, &ct_dir, &pctinfo);
	wfptk("indev=[%s] outdev=[%s] skb->nfctinfo=%d  ct_dir=%d  ct=%p \n", in ? in->name : "null", out ? out->name : "null", skb->nfctinfo, ct_dir, ct);
	if(ct){
		ct_status_2_str(ct, strbuf, sizeof(strbuf));
		wfptk("conn status=[%s] ext-len=%d\n", strbuf, ct->ext ? ct->ext->len : 0);
	}
	
	return NF_ACCEPT;
}

static struct nf_hook_ops wf_after_conntrack_in_hookops[] = 
{
	{
		.hook = wf_after_conntrack_in,
#if LINUX_VERSION_CODE == KERNEL_VERSION(2,6,12)
		.fnname = "wf_after_conntrack_in",
#endif
		.owner = THIS_MODULE,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_CONNTRACK + 1,
	//	.priority = INT_MIN,
	},
	{
		.hook = wf_after_conntrack_in,
#if LINUX_VERSION_CODE == KERNEL_VERSION(2,6,12)
		.fnname = "wf_after_conntrack_in",
#endif
		.owner = THIS_MODULE,
		.pf = PF_INET,
		.hooknum = NF_INET_LOCAL_OUT,
		.priority = NF_IP_PRI_CONNTRACK + 1,
	//	.priority = INT_MIN,
	},

};





static struct proc_dir_entry *proc_wf = NULL;
static struct proc_dir_entry *proc_wf_misc = NULL;
static struct proc_dir_entry *proc_wf_netlink_id = NULL;
static struct proc_dir_entry *proc_wf_netlink_grp_id = NULL;
static struct proc_dir_entry *proc_broadcast_hello = NULL;


static char wf_hello_info[64] = "hello: wf";

#define WF_NETLINK_PAYLOAD 8192
struct sock *wf_netlink_sock = NULL;
struct sock *wf_netlink_grp_sock = NULL;
static int wf_netlink_id = 0;
static int wf_netlink_grp_id = 0;



#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
static ssize_t wf_misc_proc_write (struct file *file, const char __user *buffer, 
				size_t count, loff_t *pos)
#else
static int wf_misc_proc_write(struct file *file, const char __user *buffer, 
				unsigned long count, void *data)
#endif
{
	uint8_t buf[128];
	uint32_t len = sizeof(buf) - 1;

	memset(buf,0,sizeof(buf));
	if(len > count)
		len = count;
		
	if(count >= sizeof(buf)){
		wfptk("size to long\n");
		return -1;
	}
	
	if(copy_from_user(buf, buffer, len))
		return count;

	if(!strncmp(buf, "hello:", 6)){
		strncpy(wf_hello_info, buf, sizeof(wf_hello_info)-1);
		if(wf_hello_info[len-1] == '\n')
			wf_hello_info[len-1] = '\0';
	}

	return count;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
static int wf_misc_proc_show(struct seq_file *s, void *p)
{
	int ret = 0;
	ret += seq_printf(s, "version: %s\n", WFKO_VERSION);
	ret += seq_printf(s, "%s\n", wf_hello_info);
	return ret;
}

static int wf_misc_open(struct inode *inode, struct file *file)
{
	return single_open(file, wf_misc_proc_show, NULL);
}

const struct file_operations wf_misc_ops = {
	.owner   = THIS_MODULE,
	.open    = wf_misc_open,
	.write   = wf_misc_proc_write,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release
};
#else
static int wf_misc_proc_read( char *page, char **start, off_t off,int count,int *eof, void *data)
{
	int len = 0;

	len += sprintf(page + len, "version: %s\n", WFKO_VERSION);
	len += sprintf(page + len, "%s\n", wf_hello_info);
	*(page + len) = 0;
	len += 1;
	
	return len;
}
#endif

static int wf_netlink_id_proc_show(struct seq_file *s, void *p)
{
	void *arg = s->private;
	s->private = NULL; // must set NULL.  do not wish kfree(seq->private) in seq_release_private
	if(arg == proc_wf_netlink_grp_id)
		return seq_printf(s, "%d\n", wf_netlink_grp_id);
	else
		return seq_printf(s, "%d\n", wf_netlink_id);
}

static int wf_netlink_id_open(struct inode *inode, struct file *file)
{
	void *arg = proc_wf_netlink_id;
	if(!strcmp(file->f_dentry->d_iname, "netlink_grp_id"))
		arg = proc_wf_netlink_grp_id;
	wfptk_debug("[%s]\n", file->f_dentry->d_iname);

	return single_open(file, wf_netlink_id_proc_show, arg);
}

static struct file_operations wf_netlink_id_ops = {
	.owner   = THIS_MODULE,
	.open    = wf_netlink_id_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release_private,
};

static ssize_t broadcast_hello_proc_write(struct file *file, const char __user *buffer, 
				size_t count, loff_t *pos)
{
	uint8_t buf[32];

	if(copy_from_user(buf, buffer, sizeof(buf) - 1))
		return count;

	if(buf[0] == '1'){
		broadcast_hello_timer.expires = jiffies + 1*HZ;
		add_timer(&broadcast_hello_timer);
	}
	else if(buf[0] == '0')
		del_timer(&broadcast_hello_timer);

	return count;
}

static int broadcast_hello_proc_show(struct seq_file *s, void *p)
{
	return seq_printf(s, "%lu\n", broadcast_hello_timer.expires);
}

static int broadcast_hello_open(struct inode *inode, struct file *file)
{
	return single_open(file, broadcast_hello_proc_show, NULL);
}

const struct file_operations broadcast_hello_ops = {
	.owner	 = THIS_MODULE,
	.open	 = broadcast_hello_open,
	.write	 = broadcast_hello_proc_write,
	.read	 = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
};


static int wf_proc_init(void)
{
	proc_wf = proc_mkdir("wf", NULL);
	if(!proc_wf)
		wfptk_err("proc_mkdir wf failed \n");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	proc_wf_misc = proc_create("wf_misc", 0440, proc_wf, &wf_misc_ops);
#else
	if ((proc_wf_misc = create_proc_entry("wf_misc", 0, proc_wf)))	{
		proc_wf_misc->read_proc = wf_misc_proc_read;
		proc_wf_misc->write_proc = wf_misc_proc_write;
	}
#endif
	if(!proc_wf_misc)
		wfptk_err("proc_create wf_misc failed \n");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	proc_wf_netlink_id = proc_create("netlink_id", 0440, proc_wf, &wf_netlink_id_ops);
#else
	proc_wf_netlink_id = create_proc_entry("netlink_id", 0440, proc_wf);
	if (proc_wf_netlink_id)
		proc_wf_netlink_id->proc_fops = &wf_netlink_id_ops;
#endif
	if(!proc_wf_netlink_id)
			wfptk_err("proc_create netlink_id failed \n");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	proc_wf_netlink_grp_id = proc_create("netlink_grp_id", 0440, proc_wf, &wf_netlink_id_ops);
#else
	proc_wf_netlink_grp_id = create_proc_entry("netlink_grp_id", 0440, proc_wf);
	if (proc_wf_netlink_grp_id)
		proc_wf_netlink_grp_id->proc_fops = &wf_netlink_id_ops;
#endif
	if(!proc_wf_netlink_grp_id)
			wfptk_err("proc_create netlink_id failed \n");

	#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	proc_broadcast_hello = proc_create("broadcast_hello", 0440, proc_wf, &broadcast_hello_ops);
#else
	if ((proc_broadcast_hello = create_proc_entry("broadcast_hello", 0, proc_wf)))	{
		proc_broadcast_hello->proc_fops = &broadcast_hello_ops;
	}
#endif
	if(!proc_broadcast_hello)
		wfptk_err("proc_create broadcast_hello failed \n");

	return 0;
}


static int __wf_netlink_send(struct nlmsghdr *nlh, u16 *type, u16 *flags, int *index, void *data, int len)
{
	struct sk_buff *skb = NULL;
	struct nlmsghdr *_nlh = NULL;
	int offset = 0;
	int ret = 0;

	skb = netlink_alloc_skb_and_init(0, nlh->nlmsg_seq, nlh->nlmsg_pid, len, NULL);
	if (!skb ){
		wfptk_err("netlink_alloc_skb_and_init error\n");
		return -1;
	}

	_nlh = (struct nlmsghdr *)skb ->data;
	if(type)
		_nlh->nlmsg_type = *type;
	if(flags)
		_nlh->nlmsg_flags = *flags;
	if(index && netlink_skb_push_data(_nlh, &offset, (char *)index, sizeof(int))){
		wfptk_err("data too large\n");
		return -1;
	}
	if(netlink_skb_push_data(_nlh, &offset, data, len)){
		wfptk_err("data too large, len=%d\n", len);
		return -1;
	}

	ret = netlink_unicast(wf_netlink_sock, skb, nlh->nlmsg_pid, MSG_DONTWAIT);
	wfptk_debug("send: ret = %d\n", ret);
	return ret;
}

static int wf_netlink_send(struct nlmsghdr *nlh,int index, void *data, int len)
{
	return __wf_netlink_send(nlh, NULL, NULL, &index, data, len);
}

static int wf_netlink_send_ack(struct nlmsghdr * nlh, int ret_code)
{
	u16 flags = NLM_F_ACK;
	return __wf_netlink_send(nlh, NULL, &flags, NULL, &ret_code, sizeof(ret_code));
}

int wf_netlink_send_msg_2_user(pid_t pid, u32 type, void *data, int len)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	
	skb = netlink_alloc_skb_and_init(type, 0, pid, len, NULL);
	if (!skb ){
		wfptk_err("netlink_alloc_skb_and_init error\n");
		return -1;
	}
	nlh = (struct nlmsghdr *)skb ->data;
	nlh->nlmsg_flags = NLM_F_REQUEST;

	return netlink_send_data(wf_netlink_grp_sock, skb, data, len);
}

int wf_netlink_broadcast_msg(u32 dst_groups, u32 type, void *data, int len)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	
	skb = netlink_alloc_skb_and_init(type, 0, 0, len, NULL);
	if (!skb ){
		wfptk_err("netlink_alloc_skb_and_init error\n");
		return -1;
	}
	nlh = (struct nlmsghdr *)skb ->data;
	nlh->nlmsg_flags = NLM_F_REQUEST;

	return netlink_broadcast_data(wf_netlink_grp_sock, skb, dst_groups, data, len);
}


static int wf_netlink_rcvmsg(struct sk_buff *skb, struct nlmsghdr *nlh, int *ret_code)
{
	int ret = 0;
	/* Only requests are handled by kernel now */
	if (!(nlh->nlmsg_flags&NLM_F_REQUEST)){
		wfptk_debug("NLM_F_REQUEST not set\n");
		return 0;
	}

	/* All the messages must have at least 1 byte length */
	if (nlh->nlmsg_len <= NLMSG_LENGTH(0)){
		wfptk_debug("invalid length\n");
		return 0;
	}


	return ret;
}

static void wf_netlink_recv_skb(struct sk_buff *skb)
{
	int err = 0;
	struct nlmsghdr * nlh = NULL;
	u32 rlen = 0;

	while (skb->len >= NLMSG_SPACE(0)) {
		nlh = (struct nlmsghdr *)skb->data;
		if (nlh->nlmsg_len < sizeof(*nlh) || skb->len < nlh->nlmsg_len){
			wfptk_err("pkt too small\n");
			return;
		}
		rlen = NLMSG_ALIGN(nlh->nlmsg_len);
		if (rlen > skb->len)
			rlen = skb->len;

		if(nlh->nlmsg_flags == NLM_F_ECHO){
			skb_pull(skb, NLMSG_HDRLEN);
			__wf_netlink_send(nlh, NULL, &nlh->nlmsg_flags, NULL, skb->data, skb->len);
			skb_pull(skb, rlen-NLMSG_HDRLEN);
			continue;
		}

	#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,12)
		READ_LOCK(&ip_conntrack_lock);
		err = wf_netlink_rcvmsg(skb, nlh,&err);
		READ_UNLOCK(&ip_conntrack_lock);
	#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,21)
		local_bh_disable();
		err = wf_netlink_rcvmsg(skb, nlh,&err);
		local_bh_enable();
	#endif

		wf_netlink_send_ack(nlh, err);
		skb_pull(skb, rlen);
	}
}

static void broadcast_hello_timer_func(unsigned long data)
{
	struct timer_list *ptimer = (struct timer_list *)data;
	char msg[8] = "hello ";
	int i = 0, ret = 0;

	msg[7] = '\0';
	for(i=1; i<5; i++){
		msg[6] = '0' + i;
		ret = wf_netlink_broadcast_msg((u32)i, 0, msg, sizeof(msg));
		wfptk("broadcast netlink msg to group %d  ret=%d \n", i, ret);
	}

	ptimer->expires = jiffies + 3*HZ;
	add_timer(ptimer);
}


static int __init wf_init(void)
{
	int ret = 0, netlink_id = MAX_LINKS;
	
	wfptkversion();
	wfptk("wf.ko start \n");

	ret = nf_register_hooks(wf_after_conntrack_in_hookops, ARRAY_SIZE(wf_after_conntrack_in_hookops));
	if (ret < 0) {
		wfptk("can't register wfko_prerouting_hook.\n");
	}

	wf_proc_init();

	#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	{	
    	struct netlink_kernel_cfg sock_cfg = {
    		.input = wf_netlink_recv_skb,
    	};
		struct netlink_kernel_cfg sock_grp_cfg = {
    		.groups = 32,
    	};
		for(netlink_id=MAX_LINKS-1; netlink_id>0; netlink_id--){
			if(!wf_netlink_sock){
				wf_netlink_sock = netlink_kernel_create(&init_net, netlink_id, &sock_cfg);
				wfptk("create netlink %s id=%d \n", wf_netlink_sock ? "ok" : "failed", netlink_id);
				if(wf_netlink_sock)
					wf_netlink_id = netlink_id;
			}

			if(netlink_id <= 1){
				wfptk("There is no remaining netlink id anymore \n");
				break;
			}
			--netlink_id;
			if(!wf_netlink_grp_sock){
				wf_netlink_grp_sock = netlink_kernel_create(&init_net, netlink_id, &sock_grp_cfg);
				wfptk("create netlink for grp %s id=%d \n", wf_netlink_grp_sock ? "ok" : "failed", netlink_id);
				if(wf_netlink_grp_sock)
					wf_netlink_grp_id = netlink_id;
			}
			
			if(wf_netlink_sock && wf_netlink_grp_sock)
				break;
		}
	}
	#endif


	setup_timer(&broadcast_hello_timer, broadcast_hello_timer_func, (unsigned long)&broadcast_hello_timer);
//	init_timer(&broadcast_hello_timer);
//	broadcast_hello_timer.function = broadcast_hello_timer_func;
//	broadcast_hello_timer.data = (unsigned long)&broadcast_hello_timer;

	return 0;
}

static void __exit wf_fini(void)
{
	int ret = 0;
	wfptk("wf.ko exit... \n");
	ret = del_timer(&broadcast_hello_timer);
	wfptk("ret of del_timer: %d \n", ret);
	if(wf_netlink_sock)
		netlink_kernel_release(wf_netlink_sock);
	if(wf_netlink_grp_sock)
		netlink_kernel_release(wf_netlink_grp_sock);
	if(proc_wf)
		proc_remove(proc_wf);
	nf_unregister_hooks(wf_after_conntrack_in_hookops, ARRAY_SIZE(wf_after_conntrack_in_hookops));
}


module_init(wf_init);
module_exit(wf_fini);
