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

static unsigned int netfilter_forward_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
ssize_t display_rules(struct device *dev, struct device_attribute *attr, char *buf);
ssize_t modify_rules(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);
ssize_t display_reset_log_flag(struct device *dev, struct device_attribute *attr, char *buf);
ssize_t modify_reset_log_flag(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);
int create_network_hook(void);
int create_devices(void);
int create_sysfs_devices(void);