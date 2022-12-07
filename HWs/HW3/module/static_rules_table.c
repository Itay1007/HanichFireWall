#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include "fw.h"

rule_t static_rules_table[MAX_RULES];

void prepare_static_rules_table(void) {
	printk(KERN_INFO "prepare the firewall static rules table\n");
}

void deallocate_static_rules_table(void) {
	printk(KERN_INFO "deallocate the firewall static rules table\n");
}

int check_packet_against_rules_table(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	int i;
	int is_rule_match;

	if(is_cristmas_tree_packet(skb)) {
		return NF_DROP;
	}

	if(is_irrelevant_packet(skb)) {
		return NF_ACCEPT;
	}

	for(i = 0; i < MAX_RULES; i++) {
		is_rule_match = check_rule_for_match(&static_rules_table[i], struct sk_buff *skb);
		if(is_rule_match == RULE_MATCHES) {
			static_rules_table[i].count++;
			return static_rules_table[i].action;
		}
	}

	return NF_DROP;
}

int check_rule_for_match(rule_t *table_entry_ptr, struct sk_buff *skb) {
	
}

// true if all flags are set:
// Terminate the connection flag, Urgent flag and Push data immediately flag
int is_cristmas_tree_packet(struct sk_buff *skb) {
	struct tcphdr *tcp_header = tcp_hdr(skb);
	return (tcp_header->fin == 1 && tcp_header->urg == 1 && tcp_header->psh == 1);
}

// true if ip protocol not in {tcp, udp, icmp} or
// ipv6 packet
int is_irrelevant_packet(struct sk_buff *skb) {
	struct iphdr * ip_header = ip_hdr(skb);
	int is_irrelevant_protocol = (ip_header->protocol != IPPROTO_TCP &&
		ip_header->protocol != IPPROTO_UDP &&
		ip_header->protocol != IPPROTO_ICMP);
	//TODO: fill in the missing data 
	int is_loopback_packet = 0;

	return is_irrelevant_protocol || (ip_header->version == 6) || is_loopback_packet;
}