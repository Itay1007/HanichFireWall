#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include "main.h"
#include "validation.h"
#include "utils.h"

#define RULES_ATTR_PATH "/sys/class/fw/rules/rules"
#define RESET_ATTR_PATH "/sys/class/fw/log/reset"
#define FW_LOG_DEVICE "/dev/fw_log"

// User space program that will communicate with the kernel module.
// The program get an arguments and work by them.
// The supported values are:
// •	show_rules
// •	load_rules <path_to_rules_file>
// •	show_log
// •	clear_log

// load firewall rules
// through writing
// to /sys/class/fw/rules/rules
void load_rules(char *path_to_rules_file)
{
    FILE *firewall_new_rules_file_fp;
    char rule_chars_line[500] = {0};
    rule_t rule;
    int firewall_update_rules_fp;
    //TODO: add validation of the lines of the file before using it
    firewall_new_rules_file_fp = fopen(path_to_rules_file, "r");
    firewall_update_rules_fp = open(RULES_ATTR_PATH, O_WRONLY);

    while(fgets(rule_chars_line, 500, firewall_new_rules_file_fp)) {
        printf("Validate Rule Line\n");
        printf("%s", rule_chars_line);
        validate_rules_file_line(rule_chars_line);
        printf("Valid Rule Line\n\n");
        parse_line_to_rule(&rule, rule_chars_line);
        printf("Parse rule\n");
        printf("rule name: %s\n", rule.rule_name);
        if(rule.direction == DIRECTION_ANY) {
            printf("rule.direction=0x03('any')\n");
        }
        else if(rule.direction == DIRECTION_IN) {
            printf("rule.direction=0x01('in')\n");
        }
        else if(rule.direction == DIRECTION_OUT) {
            printf("rule.direction=0x02('out')\n");
        }
        printf("rule name: %s\n", rule.rule_name);
        printf("direction: %d\n", rule.direction);
        printf("direction: %u\n", rule.direction);
        printf("source sample network ip address: %d\n", rule.src_ip);
        printf("source mask number in be: %d\n", rule.src_prefix_mask);
        printf("dest mask size: %d\n", rule.src_prefix_size);
        printf("dest sample network ip address: %d\n", rule.dst_ip);
        printf("dest mask number in be: %d\n", rule.dst_prefix_mask);
        printf("dest mask size: %d\n", rule.dst_prefix_size);
        printf("protocol number: %d\n", rule.protocol);
        printf("source port: %d\n", rule.src_port);
        printf("dest port: %d\n", rule.dst_port);
        printf("ack: %d\n", rule.ack);
        printf("action: %d\n", rule.action);
        write(firewall_update_rules_fp, &rule, sizeof(rule));
    }
    fclose(firewall_new_rules_file_fp);
    close(firewall_update_rules_fp);
}

void parse_line_to_rule(rule_t *rule_ptr, char* rule_chars_line) {
    int i = 0, j = 0;
    int rule_element_i = 0;
    direction_t direction;
    char rule_line_token[20];
    char ip[20];
    char mask[3];
    unsigned int be_ip_number;
    unsigned char mask_size;

    for(rule_element_i = 0; rule_element_i < 8; rule_element_i) {
        for(; isspace(rule_chars_line[i]); i++) {
            i++;
        }

        for(j = 0; !isspace(rule_chars_line[i]); i++, j++) {
            rule_line_token[j] = rule_chars_line[i]; 
        }
        rule_line_token[j] = '\0';

        switch(rule_element_i) {
            case 0: for(j = 0; rule_chars_line[j]; j++) {
                        rule_ptr->rule_name[j] = rule_chars_line[j];
                    }
                    rule_ptr->rule_name[j] = '\0';
                    break;
            case 1: if(!strncmp(rule_line_token, "in", strlen("in"))) {
                        printf("direction in\n");
                        direction = DIRECTION_IN;
                    }
                    else if(!strncmp(rule_line_token, "out", strlen("out"))) {
                        printf("direction out\n");
                        direction = DIRECTION_OUT;
                    }
                    else {
                        printf("direction any\n");
                        direction = DIRECTION_ANY;
                    }
                    printf("direction=%d\n", direction);
                    rule_ptr->direction = direction;
                    break;
            case 2: if (!strncmp(rule_line_token, "any", strlen("any"))) {
                        rule_ptr->src_ip = 0;
                    }
                    fill_ip_mask(ip, mask, rule_line_token);
                    be_ip_number = make_be_ip_number(ip);
                    rule_ptr->src_ip = be_ip_number;
                    mask_size = atoi(mask);
                    rule_ptr->src_prefix_mask = make_network_mask_size_ip_be_number(mask_size);
                    rule_ptr->src_prefix_size = mask_size;
                    break;
            case 3: if (!strncmp(rule_line_token, "any", strlen("any"))) {
                        rule_ptr->dst_ip = 0;
                    }
                    fill_ip_mask(ip, mask, rule_line_token);
                    be_ip_number = make_be_ip_number(ip);
                    rule_ptr->dst_ip = be_ip_number;
                    mask_size = atoi(mask);
                    rule_ptr->dst_prefix_mask = make_network_mask_size_ip_be_number(mask_size);
                    rule_ptr->dst_prefix_size= mask_size;
                    break;
            case 4: if(!strncmp(rule_line_token, "TCP", strlen("TCP"))) {
                        rule_ptr->protocol = PROT_TCP;
                    }
                    else if(!strncmp(rule_line_token, "UDP", strlen("UDP"))) {
                        rule_ptr->protocol = PROT_UDP;
                    }
                    else if(!strncmp(rule_line_token, "ICMP", strlen("ICMP"))) {
                        rule_ptr->protocol = PROT_ICMP;
                    }
                    else {
                        rule_ptr->protocol = PROT_ANY;
                    }
                    break;
            case 5: rule_ptr->src_port = atoi(rule_line_token);
                    break;
            case 6: rule_ptr->dst_port = atoi(rule_line_token);
                    break;
            case 7: if(!strncmp(rule_line_token, "yes", strlen("yes"))) {
                        rule_ptr->ack = ACK_YES;
                    }
                    else if(!strncmp(rule_line_token, "no", strlen("no"))) {
                        rule_ptr->ack = ACK_NO;
                    }
                    else {
                        rule_ptr->ack = ACK_ANY;
                    }
                    break;
            case 8: if(!strncmp(rule_line_token, "accept", strlen("accept"))) {
                        rule_ptr->action = NF_ACCEPT;
                    }
                    else {
                        rule_ptr->action = NF_DROP;
                    }
                    break;
            default:
                    printf("File contains invalid number of columns in a line. No {FIREWALL_TABLE_COLMUNS_NUM}\n");
                    exit(0);
        }
        rule_element_i++;    
    }
}

// show firewall rules
// through reading
// from /sys/class/fw/rules/rules
void show_rules(void)
{
    int i;
    int show_fw_rules_fp;
    // TODO: fix this to the real size of the rule structure from fw.h
    unsigned int RULE_SIZE = 100;
    // TODO: fix this to the real log structure from fw.h
    char rule_buffer[100];

    show_fw_rules_fp = open(RULES_ATTR_PATH, O_RDONLY);

    // TODO: add a loop for reading and printing all the rules
    while (0)
    {
        read(show_fw_rules_fp, rule_buffer, RULE_SIZE);
    }
    // TODO: parse the <rule_buffer> into the fields and print the fields
    printf("rule\n");
    close(show_fw_rules_fp);
}

// show firewall logs
// through reading
// from /dev/fw_log
void show_log(void)
{
    int i;
    int fw_logs_fp;
    // TODO: fix this to the real size of the log structure from fw.h
    unsigned int PACKET_LOG_SIZE = 100;
    // TODO: fix this to the real log structure from fw.h
    char log_buffer[100];

    fw_logs_fp = open(FW_LOG_DEVICE, O_RDONLY);

    // TODO: add a loop for reading and printing all the logs
    while (0)
    {
        read(fw_logs_fp, log_buffer, PACKET_LOG_SIZE);
    }
    // TODO: parse the <log_buffer> into the fields and print the fields
    printf("packet log\n");
    close(fw_logs_fp);
}

// clear firewall logs
// through writing anything (N/A)
// to /sys/class/fw/log/reset
void clear_log(void)
{
    int fw_logs_reset_fp;
    int fw_logs_clear_fp;

    // deallocate the log resources
    fw_logs_reset_fp = open(RESET_ATTR_PATH, O_WRONLY);
    write(fw_logs_reset_fp, "0", strlen("0"));
    close(fw_logs_reset_fp);

    // clear the file from the logs using the write flag
    fw_logs_clear_fp = open(FW_LOG_DEVICE, O_WRONLY);
    write(fw_logs_clear_fp, "0", strlen("0"));
    close(fw_logs_clear_fp);
}

int main(int argc, char *argv[])
{
    validate_user_input(argc, argv);

    if (!strncmp(argv[1], "load_rules", strlen("load_rules")))
    {
        load_rules(argv[2]);
    }
    else if (!strncmp(argv[1], "show_rules", strlen("show_rules")))
    {
        show_rules();
    }
    else if (!strncmp(argv[1], "show_log", strlen("show_log")))
    {
        show_log();
    }
    else if (!strncmp(argv[1], "clear_log", strlen("clear_log")))
    {
        clear_log();
    }
}