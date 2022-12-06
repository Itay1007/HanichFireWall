#include <linux/kernel.h>
#include <linux/module.h>

void prepare_static_rules_table(void) {
	printk(KERN_INFO "prepare the firewall static rules table\n");
}

void deallocate_static_rules_table(void) {
	printk(KERN_INFO "deallocate the firewall static rules table\n");
}
