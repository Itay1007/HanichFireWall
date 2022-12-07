#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/fs.h>
#include <linux/device.h>

#define NF_DROP 0
#define NF_ACCEPT 1

#define PACKET_IN_NETFILTER_HOOK "***Packet in netfilter hook***"
#define PACKET_ACCEPT_MESSAGE "***Packet Accept***"
#define PACKET_DROP_MESSAGE "***Packet Drop***"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Itay Barok");

static unsigned int netfilter_forward_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

ssize_t display_rules(struct device *dev, struct device_attribute *attr, char *buf);
ssize_t modify_rules(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);

ssize_t display_reset_log_flag(struct device *dev, struct device_attribute *attr, char *buf);
ssize_t modify_reset_log_flag(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);

int fw_log_open(struct inode *inode, struct file *file);
ssize_t fw_log_read(struct file *filp, char *buffer, size_t length, loff_t *offset);

int create_network_hook(void);
int create_devices(void);
int create_sysfs_devices(void);
int create_device(void);

static int __init my_module_init_function(void);
static void __exit my_module_exit_function(void);