#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "validation.h"

#define FIREWALL_TABLE_COLMUNS_NUM 9

void validate_user_input(int argc, char *argv[]) {
    int i;
    char *firewall_commands[3] = {"show_rules", "show_log", "clear_log"};
    char *firewall_command;

    printf("validate user input\n");

    if ((argc == 3) && (!strncmp(argv[1], "load_rules", strlen("load_rules")))) {
        return;
    }

    if(argc != 2) {
        printf("Usage:\n./main.py [show_rules/show_log/clear_log] or\n./main.py load_rules <path_to_rules_file>\n");
        exit(0);       
    }

    for(i = 0; i < 3; i++) {
        firewall_command = firewall_commands[i];
        if(!strncmp(argv[1], firewall_command, strlen(firewall_command))) {
            return;
        }
    }

    printf("Usage:\n./main.py [show_rules/show_log/clear_log] or\n./main.py load_rules <path_to_rules_file>\n");
    exit(0);
}

void validate_rules_file_line(char *rule_line) {
    int rule_element_i = 0;
    char *rule_line_token = strtok(rule_line, " ");
    char *ip_token;

    while(rule_line_token != NULL) {
        printf("Validation on element %d\n", rule_element_i);
        printf("%s\n", rule_line_token);

        switch(rule_element_i) {
            case 0: validate_rule_name(rule_line_token);
                    break;
            case 1: validate_direction(rule_line_token);
                    break;
            case 2: if (strncmp(rule_line_token, "any", strlen("any"))) {
                            validate_ip_mask(rule_line_token);
                    }
                    break;
            case 3: if (strncmp(rule_line_token, "any", strlen("any"))) {
                            validate_ip_mask(rule_line_token);
                    }
                    break;
            case 4: validate_protocol(rule_line_token);
                    break;
            case 5: validate_port(rule_line_token);
                    break;
            case 6: validate_port(rule_line_token);
                    break;
            case 7: validate_ack(rule_line_token);
                    break;        
            case 8: validate_action(rule_line_token);
                    break;
            default:
                    printf("File contains invalid number of columns in a line. No {FIREWALL_TABLE_COLMUNS_NUM}\n");
                    exit(0);
        }
        rule_element_i++;
        rule_line_token = strtok(NULL, " ");
    }
}

void validate_rule_name(char *rule_name) {
    if(strlen(rule_name) <= 20) {
        return;
    }
    printf("Rule Name should be at most 20 characters long. Invalid rule name { {rule_name}");
    exit(0);
}

void validate_direction(char *direction) {
    int i = 0;
    char *firewall_directions[3] = {"in", "out", "any"};
    char *firewall_direction;

    for(i = 0; i < 4; i++) {
        firewall_direction = firewall_directions[i];
        if(!strncmp(direction, firewall_direction, strlen(firewall_direction))) {
            return;
        }
    }

    printf("Direction field in rule table is from ['in', 'out', 'any']. Invalid given direction %s", direction);
    exit(0);
}

void validate_ip_mask(char *rule_line_token) {
    int i;
    int j = 0;
    char sep = '/';
    char ip[20];
    char mask[2];

    for(i = 0, j = 0; rule_line_token[i] != sep; i++, j++) {
        ip[j] = rule_line_token[i];
    }

    for (i++, j = 0 ; rule_line_token[i] && j < 2; i++, j++)
    {
        printf("mask[%d]=%c(%d)\n", j, rule_line_token[i], rule_line_token[i]);
        mask[j] = rule_line_token[i]; 
    }

    validate_ip(ip);
    validate_mask(mask);
}

void validate_ip(char *ip) {
    int ip_octet_number = -1;
    int ip_octets_counter = 0;
    char *ip_octet = strtok(ip, ".");
    while(ip_octet != NULL) {
        if(strncmp(ip_octet, "0", 1) && (((ip_octet_number = atoi(ip_octet)) == 0) || (ip_octet_number < 0) || (255 < ip_octet_number))) {
            printf("Invalid ip octet %s\n", ip_octet);
            exit(0);    
        }
        ip_octets_counter++;
        ip_octet = strtok(NULL, ".");
    }

    if(ip_octets_counter != 4) {
        printf("Invalid source ip %s", ip);
        exit(0);
    } 
}

void validate_mask(char *mask) {
    int mask_number;
    printf("validate mask.\n");
    printf("%s\n", mask);

    if(!strncmp(mask, "0", strlen("0"))) {
        return;
    }

    if(((mask_number = atoi(mask)) != 0) && (0 <= mask_number) && (mask_number < 32)) {
        return;
    }

    printf("Invalid mask %s. Should be int from [0, 31]", mask);
    exit(0);
}

void validate_protocol(char *protocol_name) {
    int i = 0;
    char *firewall_protocols[4] = {"TCP", "UDP", "ICMP", "any"};
    char *firewall_protocol;

    for(i = 0; i < 4; i++) {
        firewall_protocol = firewall_protocols[i];
        if(!strncmp(protocol_name, firewall_protocol, strlen(firewall_protocol))) {
            return;
        }
    }

    printf("Invalid protocol name %s. Not in ['TCP', 'UDP', 'ICMP', 'any']", protocol_name);
    exit(0);
}

void validate_port(char *port) {
    int port_number = -1;
    if(!strncmp(port, "0", strlen("0"))) {
        return;
    }

    if(((port_number = atoi(port)) != 0) && (port_number < 1023)) {
        return;
    }

    if((port[0] == '>') && ((port_number = atoi(port + 1)) != 0) && (port_number == 1023)) {
        return;
    }

    printf("Invalid port\n");
    exit(0);
}

void validate_ack(char *ack) {
    int i = 0;
    char *firewall_ack_values[3] = {"yes", "no", "any"};
    char *firewall_ack_value;

    for(i = 0; i < 4; i++) {
        firewall_ack_value = firewall_ack_values[i];
        if(!strncmp(ack, firewall_ack_value, strlen(firewall_ack_value))) {
            return;
        }
    }
    printf("Invalid ack %s. Not in ['yes', 'no', 'any']\n", ack);
    exit(0);
}

void validate_action(char *action) {
    int i = 0;
    char *firewall_action_values[3] = {"accept", "drop"};
    char *firewall_action_value;

    for(i = 0; i < 4; i++) {
        firewall_action_value = firewall_action_values[i];
        if(!strncmp(action, firewall_action_value, strlen(firewall_action_value))) {
            return;
        }
    }

    printf("Invaild action %s. Not in ['accept', 'drop']\n", action);
    exit(0);        
}