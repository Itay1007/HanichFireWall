#include "hw3secws.h"

static struct nf_hook_ops *nf_net_forward_hook = NULL;

static int major_number;
static struct class* sysfs_class = NULL;
static struct device* sysfs_device = NULL;


static unsigned int accepted_packets_counter = 0;
static unsigned int dropped_packets_counter = 0;

static struct file_operations fops = {
	.owner = THIS_MODULE
};

// drop packets that go through the firewall to another host.
// The firewall drops the packets and log it in kernel ring
static unsigned int netfilter_forward_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	printk(KERN_INFO DROP_PACKET_MESSAGE);
	dropped_packets_counter++;
	return NF_DROP;
}

// sysfs show function, the function that read from the attribute to the user
ssize_t display_rules(struct device *dev, struct device_attribute *attr, char *buf) {
	return scnprintf(buf, PAGE_SIZE, "%u\n", accepted_packets_counter);
}

// sysfs store function, the function that writes to the attribute from the user
ssize_t modify_rules(struct device *dev, struct device_attribute *attr, const char *buf, size_t count) {
	int temp;
	if(sscanf(buf,"%u", &temp) == 1) {
		accepted_packets_counter = temp;
	}
	return count;
}

ssize_t display_reset_log_flag(struct device *dev, struct device_attribute *attr, char *buf) {
	return scnprintf(buf, PAGE_SIZE, "%u\n", accepted_packets_counter);
}

// sysfs store function, the function that writes to the attribute from the user
ssize_t modify_reset_log_flag(struct device *dev, struct device_attribute *attr, const char *buf, size_t count) {
	int temp;
	if(sscanf(buf,"%u", &temp) == 1) {
		dropped_packets_counter = temp;
	}
	return count;
}


static DEVICE_ATTR(rules, S_IWUSR | S_IRUGO, display_rules, modify_rules);
static DEVICE_ATTR(reset, S_IWUSR | S_IRUGO, display_reset_log_flag, modify_reset_log_flag);

int create_network_hook() {
	nf_net_forward_hook = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);

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

	return 0;
}

int create_devices() {
	if(create_sysfs_devices() != 0) {
		return -1;
	}

	return 0;
}

int create_sysfs_devices() {
	major_number = register_chrdev(0, "Sysfs_Device", &fops);\
	if(major_number < 0) {
		return -1;
	}

	sysfs_class = class_create(THIS_MODULE, "fw");
	if(IS_ERR(sysfs_class)) {
		unregister_chrdev(major_number, "Sysfs_Device");
		return -1;	
	}

	sysfs_device = device_create(sysfs_class, NULL, MKDEV(major_number, 0), NULL, "rules");
	if(IS_ERR(sysfs_device)) {
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "Sysfs_Device");
		return -1;
	}

	if(device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_rules.attr)){
		device_destroy(sysfs_class, MKDEV(major_number, 0));
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "Sysfs_Device");
		return -1;
	}

	if(device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_reset.attr)){
		device_destroy(sysfs_class, MKDEV(major_number, 0));
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "Sysfs_Device");
		return -1;
	}

	return 0;	
}


// init function that is called when the module is loaded to the kernel
static int __init my_module_init_function(void) {
	if(create_netowrk_hook() != 0) {
		return -1;
	}

	if(create_devices() != 0) {
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

	device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_reset.attr);
	device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_rules.attr);
	device_destroy(sysfs_class, MKDEV(major_number, 0));
	class_destroy(sysfs_class);
	unregister_chrdev(major_number, "Sysfs_Device");
}


module_init(my_module_init_function);
module_exit(my_module_exit_function);
