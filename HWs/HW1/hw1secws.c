#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#define NF_DROP 0
#define NF_ACCEPT 1
#define ACCEPT_PACKET_MESSAGE "*** Packet Accepted ***"
#define DROP_PACKET_MESSAGE "*** Packet Dropped ***"

MODULE_LICENSE("GPL");

static struct nf_hook_ops *nf_net_forward_hook = NULL;
static struct nf_hook_ops *nf_net_local_in_hook = NULL;
static struct nf_hook_ops *nf_net_local_out_hook = NULL;


// drop packets that go through the firewall to another host.
// The firewall drops the packets and log it in kernel ring
static unsigned int netfilter_forward_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	//printk(KERN_INFO "Hook Function Forward!\n");
	printk(KERN_INFO DROP_PACKET_MESSAGE);
	return NF_DROP;
}

// accept packets that go in to the firewall to another host.
// The firewall accepts the packets and log it in kernel ring
static unsigned int netfilter_local_in_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	//printk(KERN_INFO "Hook Function Local In!\n");
	printk(KERN_INFO ACCEPT_PACKET_MESSAGE);
	return NF_ACCEPT;
}

// accept packets that go from the firewall to another host.
// The firewall accepts the packets and log it in kernel ring
static unsigned int netfilter_local_out_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	//printk(KERN_INFO "Hook Function Local Out!\n");
	printk(KERN_INFO ACCEPT_PACKET_MESSAGE);
	return NF_ACCEPT;
}


// init function that is called when the module is loaded to the kernel
static int __init my_module_init_function(void) {
	//printk(KERN_INFO "Hello World Init Module!\n");
	
	nf_net_forward_hook = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	
	nf_net_local_in_hook = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	
	nf_net_local_out_hook = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);

	if(nf_net_forward_hook != NULL) {
		nf_net_forward_hook->hook = (nf_hookfn*)netfilter_forward_hook;
		nf_net_forward_hook->hooknum = NF_INET_FORWARD;
		nf_net_forward_hook->pf = PF_INET;
		nf_net_forward_hook->priority = 0;

		nf_register_net_hook(&init_net, nf_net_forward_hook);
	}	

	if(nf_net_local_in_hook != NULL) {
		nf_net_local_in_hook->hook = (nf_hookfn*)netfilter_local_in_hook;
		nf_net_local_in_hook->hooknum = NF_INET_LOCAL_IN;
		nf_net_local_in_hook->pf = PF_INET;
		nf_net_local_in_hook->priority = 0;

		nf_register_net_hook(&init_net, nf_net_local_in_hook);
	}	

	if(nf_net_local_out_hook != NULL) {
		nf_net_local_out_hook->hook = (nf_hookfn*)netfilter_local_out_hook;
		nf_net_local_out_hook->hooknum = NF_INET_LOCAL_OUT;
		nf_net_local_out_hook->pf = PF_INET;
		nf_net_local_out_hook->priority = 0;

		nf_register_net_hook(&init_net, nf_net_local_out_hook);
	}	

	return 0;
}

// exit function that is called when the module is removed from the kernel
static void __exit my_module_exit_function(void) {
	if(nf_net_forward_hook != NULL) {
		nf_unregister_net_hook(&init_net, nf_net_forward_hook);
		kfree(nf_net_forward_hook);
	}

	if(nf_net_local_in_hook != NULL) {
		nf_unregister_net_hook(&init_net, nf_net_local_in_hook);
		kfree(nf_net_local_in_hook);
	}

	if(nf_net_local_out_hook != NULL) {
		nf_unregister_net_hook(&init_net, nf_net_local_out_hook);
		kfree(nf_net_local_out_hook);
	}

	// printk(KERN_INFO "Goodbye World Exit Module!\n");
}


module_init(my_module_init_function);
module_exit(my_module_exit_function);
