#ifndef _VALIDATION_H_
#define _VALIDATION_H_

#define FIREWALL_TABLE_COLMUNS_NUM 9

void validate_user_input(int argc, char *argv[]); 
void validate_rules_file_line(char *rule_line); 
void validate_rule_name(char *rule_name);
void validate_direction(char *direction);
void validate_ip(char *ip);
void validate_mask(char *mask);
void validate_protocol(char *protocol_name);
void validate_port(char *port);
void validate_ack(char *ack);
void validate_action(char *action);

#endif // _VALIDATION_H_