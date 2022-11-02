#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#define NF_DROP 0
#define NF_ACCEPT 1

static struct nf_hook_ops *nf_net_hook = NULL;


static unsigned int netfilter_hookfn(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	printk(KERN_INFO "In hook function!\n");

	if(!skb) {
		printk(KERN_INFO "skb is null in hook function\n");
		return NF_ACCEPT;
	}
	return NF_ACCEPT;
}


// init function that is called when the module is loaded to the kernel
static int __init my_module_init_function(void) {
	printk(KERN_INFO "Hello World!\n");
	
	nf_net_hook = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	
	if(nf_net_hook != NULL) {
		nf_net_hook->hook = (nf_hookfn*)netfilter_hookfn;
		nf_net_hook->hooknum = NF_INET_PRE_ROUTING;
		nf_net_hook->pf = 0;
		nf_net_hook->priority = 0;

		nf_register_net_hook(&init_net, nf_net_hook);
	}	

	return 0;
}

// exit function that is called when the module is removed from the kernel
static void __exit my_module_exit_function(void) {
	if(nf_net_hook != NULL) {
		nf_unregister_net_hook(&init_net, nf_net_hook);
		kfree(nf_net_hook);
	}

	printk(KERN_INFO "Goodbye World!\n");
}


module_init(my_module_init_function);
module_exit(my_module_exit_function);
