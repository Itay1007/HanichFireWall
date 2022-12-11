#include "fw.h"
#include "static_rules_table.h"

rule_t static_rules_table[MAX_RULES];
unsigned int number_of_rules_in_table = 0;

void prepare_static_rules_table(void) {
	printk(KERN_INFO "prepare the firewall static rules table\n");
}

void add_static_table_rule(const char *buf) {
	if(number_of_rules_in_table >= 50) {
		printk(KERN_INFO "Tried insert another rule to a full static rules table\n");
		return;
	}

	printk(KERN_INFO "copy from user\n");
	copy_from_user(&static_rules_table[number_of_rules_in_table], buf, sizeof(rule_t));
	print_rule_kernel_mode(&static_rules_table[number_of_rules_in_table]);
	number_of_rules_in_table++;
}

void print_rule_kernel_mode(rule_t *rule_ptr) {
        printk("Data of a rule:\n");
        printk("rule name: %s\n", rule_ptr->rule_name);
        printk("direction: %d\n", rule_ptr->direction);
        printk("source sample network ip address: %d\n", rule_ptr->src_ip);
        printk("source mask number in be: %d\n", rule_ptr->src_prefix_mask);
        printk("dest mask size: %d\n", rule_ptr->src_prefix_size);
        printk("dest sample network ip address: %d\n", rule_ptr->dst_ip);
        printk("dest mask number in be: %d\n", rule_ptr->dst_prefix_mask);
        printk("dest mask size: %d\n", rule_ptr->dst_prefix_size);
        printk("protocol number: %d\n", rule_ptr->protocol);
        printk("source port: %d\n", rule_ptr->src_port);
        printk("dest port: %d\n", rule_ptr->dst_port);
        printk("ack: %d\n", rule_ptr->ack);
        printk("action: %d\n", rule_ptr->action);
}

void delete_static_rule_table() {
	memset(static_rules_table, 0 , sizeof(static_rules_table));
	number_of_rules_in_table = 0;
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

	for(i = 0; i < number_of_rules_in_table; i++) {
		is_rule_match = check_rule_for_match(&static_rules_table[i], skb);
		if(is_rule_match == RULE_MATCHES) {
			//TODO add this to the log
			return static_rules_table[i].action;
		}
	}
	//TODO add this to the log
	return NF_DROP;
}

int check_rule_for_match(rule_t *table_entry_ptr, struct sk_buff *skb) {
	struct tcphdr *tcp_header = tcp_hdr(skb);
	struct iphdr * ip_header = ip_hdr(skb);
	
	//TODO: check the direction field

	// check if saddr is in the netowrk src_ip/src_prefix_size
	if(table_entry_ptr->src_ip != 0 &&
	  (ip_header->saddr & table_entry_ptr->src_prefix_mask) != (table_entry_ptr->src_ip & table_entry_ptr->src_prefix_mask)) {
		return RULE_DOESNOT_MATCHES;
	}

	// check if daddr is in the netowrk dst_ip/dst_prefix_size
	if(table_entry_ptr->dst_ip != 0 &&
	  (ip_header->daddr & table_entry_ptr->dst_prefix_mask) != (table_entry_ptr->dst_ip & table_entry_ptr->dst_prefix_mask)) {
		return RULE_DOESNOT_MATCHES;
	}

	if(table_entry_ptr->protocol != PROT_ANY && ip_header->protocol != table_entry_ptr->protocol) {
		return RULE_DOESNOT_MATCHES;
	}

	if(table_entry_ptr->src_port != 0 && tcp_header->source != table_entry_ptr->src_port) {
		return RULE_DOESNOT_MATCHES;
	}

	if(table_entry_ptr->dst_port != 0 && tcp_header->dest != table_entry_ptr->dst_port) {
		return RULE_DOESNOT_MATCHES;
	}

	if(table_entry_ptr->ack != ACK_ANY && tcp_header->ack != table_entry_ptr->ack) {
		return RULE_DOESNOT_MATCHES;
	}

	return RULE_MATCHES;
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