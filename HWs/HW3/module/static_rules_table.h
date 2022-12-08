#include "fw.h"

void prepare_static_rules_table(void);
void deallocate_static_rules_table(void);
void delete_static_rule_table(void);
int check_packet_against_rules_table(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
int check_rule_for_match(rule_t *table_entry_ptr, struct sk_buff *skb);
int is_cristmas_tree_packet(struct sk_buff *skb);
int is_irrelevant_packet(struct sk_buff *skb);
