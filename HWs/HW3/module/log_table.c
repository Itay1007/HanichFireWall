#include <linux/kernel.h>
#include <linux/module.h>

void prepare_log_table(void) {
	printk(KERN_INFO "prepare the log table\n");
}

void deallocate_log_table(void) {
	printk(KERN_INFO "deallocate log table\n");
}
