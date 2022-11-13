#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/fs.h>
#include <linux/device.h>

#define NF_DROP 0
#define NF_ACCEPT 1
#define ACCEPT_PACKET_MESSAGE "*** Packet Accepted ***"
#define DROP_PACKET_MESSAGE "*** Packet Dropped ***"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Itay Barok");

static struct nf_hook_ops *nf_net_forward_hook = NULL;
static struct nf_hook_ops *nf_net_local_in_hook = NULL;
static struct nf_hook_ops *nf_net_local_out_hook = NULL;

static int major_number;
static struct class* sysfs_class = NULL;
static struct device* sysfs_device = NULL;

static unsigned int sysfs_int = 0;

static struct file_operations fops = {
	.owner = THIS_MODULE
};

// drop packets that go through the firewall to another host.
// The firewall drops the packets and log it in kernel ring
static unsigned int netfilter_forward_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	printk(KERN_INFO DROP_PACKET_MESSAGE);
	return NF_DROP;
}

// accept packets that go in to the firewall to another host.
// The firewall accepts the packets and log it in kernel ring
static unsigned int netfilter_local_in_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	printk(KERN_INFO ACCEPT_PACKET_MESSAGE);
	return NF_ACCEPT;
}

// accept packets that go from the firewall to another host.
// The firewall accepts the packets and log it in kernel ring
static unsigned int netfilter_local_out_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	printk(KERN_INFO ACCEPT_PACKET_MESSAGE);
	return NF_ACCEPT;
}

// sysfs show function, the function that read from the attribute to the user
ssize_t display_dropped_packets_counter(struct device *dev, struct device_attribute *attr, char *buf) {
	return scnprintf(buf, PAGE_SIZE, "%u\n", sysfs_int);
}


// sysfs store function, the function that writes to the attribute from the user
ssize_t modify_dropped_packets_counter(struct device *dev, struct device_attribute *attr, const char *buf, size_t count) {
	int temp;
	if(sscanf(buf, "%u", &temp) == 1) {
		sysfs_int = temp;
	}

	return count;
}

static DEVICE_ATTR(sysfs_att, S_IWUSR | S_IRUGO, display_dropped_packets_counter, modify_dropped_packets_counter);

// init function that is called when the module is loaded to the kernel
static int __init my_module_init_function(void) {
	nf_net_forward_hook = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	
	nf_net_local_in_hook = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	
	nf_net_local_out_hook = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);

	if(nf_net_forward_hook != NULL) {
		nf_net_forward_hook->hook = (nf_hookfn*)netfilter_forward_hook;
		nf_net_forward_hook->hooknum = NF_INET_FORWARD;
		nf_net_forward_hook->pf = PF_INET;
		nf_net_forward_hook->priority = 0;

		if(nf_register_net_hook(&init_net, nf_net_forward_hook)) {
			return -1;
		}
	}
	else {
		return -1;
	}	

	if(nf_net_local_in_hook != NULL) {
		nf_net_local_in_hook->hook = (nf_hookfn*)netfilter_local_in_hook;
		nf_net_local_in_hook->hooknum = NF_INET_LOCAL_IN;
		nf_net_local_in_hook->pf = PF_INET;
		nf_net_local_in_hook->priority = 0;

		if(nf_register_net_hook(&init_net, nf_net_local_in_hook)) {
			return -1;	
		}
	}
	else {
		return -1;
	}	

	if(nf_net_local_out_hook != NULL) {
		nf_net_local_out_hook->hook = (nf_hookfn*)netfilter_local_out_hook;
		nf_net_local_out_hook->hooknum = NF_INET_LOCAL_OUT;
		nf_net_local_out_hook->pf = PF_INET;
		nf_net_local_out_hook->priority = 0;

		if(nf_register_net_hook(&init_net, nf_net_local_out_hook)) {
			return -1;
		}
	}
	else {
		return -1;
	}

	major_number = register_chrdev(0, "Sysfs_Device", &fops);
	if(major_number < 0) {
		return -1;
	}

	sysfs_class = class_create(THIS_MODULE, "Sysfs_class");
	if(IS_ERR(sysfs_class)) {
		unregister_chrdev(major_number, "Sysfs_Device");
		return -1;	
	}

	sysfs_device = device_create(sysfs_class, NULL, MKDEV(major_number, 0), NULL, "sysfs_class" "_" "sysfs_Device");
	if(IS_ERR(sysfs_device)) {
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "Sysfs_Device");
		return -1;
	}

	if(device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_sysfs_att.attr)){
		device_destroy(sysfs_class, MKDEV(major_number, 0));
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "Sysfs_Device");
		return -1;
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

	device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_sysfs_att.attr);
	device_destroy(sysfs_class, MKDEV(major_number, 0));
	class_destroy(sysfs_class);
	unregister_chrdev(major_number, "Sysfs_Device");
}


module_init(my_module_init_function);
module_exit(my_module_exit_function);
