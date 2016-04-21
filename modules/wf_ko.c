#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/if_ether.h>

#define wfptk(fmt, ...)		printk(KERN_INFO"WFKO[%s:%d] "fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)


unsigned int wfko_prerouting(unsigned int hooknum,
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

	if(skb)
		wfptk("skb \n");
	
	return NF_ACCEPT;
}

static struct nf_hook_ops wfko_prerouting_hook = {
	.hook = wfko_prerouting,
	#if LINUX_VERSION_CODE == KERNEL_VERSION(2,6,12)
	.fnname = "wfko_prerouting",
	#endif
	.owner = THIS_MODULE,
	.pf = PF_INET,
	.hooknum = NF_INET_PRE_ROUTING,
	.priority = INT_MIN,
};


static int __init wf_ko_init(void)
{
	int ret = 0;
	wfptk("wf.ko start \n");

	ret = nf_register_hook(&wfko_prerouting_hook);
	if (ret < 0) {
		wfptk("can't register wfko_prerouting_hook.\n");
	}

	return 0;
}

static void __exit wf_ko_fini(void)
{
	nf_unregister_hook(&wfko_prerouting_hook);
	wfptk("wf.ko exit \n");
}


module_init(wf_ko_init);
module_exit(wf_ko_fini);
