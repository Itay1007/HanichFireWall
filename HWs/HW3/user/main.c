#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <unistd.h>
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
    FILE *firewall_update_rules_fp;
    char rule_chars_line[500] = {0};
    rule_t rule;
    //TODO: add validation of the lines of the file before using it
    firewall_new_rules_file_fp = fopen(path_to_rules_file, "r");

    while(fgets(rule_chars_line, 500, firewall_new_rules_file_fp)) {
        printf("%s\n", rule_chars_line);
        validate_rules_file_line(rule_chars_line);
        parse_line_to_rule(&rule, rule_chars_line);
        write(firewall_update_rules_fp, &rule, sizeof(rule));
    }
    close(firewall_new_rules_file_fp);
    close(firewall_update_rules_fp);
}

void parse_line_to_rule(rule_t *rule_ptr, char* rule_chars_line) {
    int rule_element_i = 0;
    direction_t direction;
    char *rule_line_token = strtok(rule_chars_line, " ");
    char *ip_token;
    unsigned int be_ip_number;
    char *mask_token;

    while(rule_line_token != NULL) {
        switch(rule_element_i) {
            case 0: strncpy(rule_ptr->rule_name, rule_line_token, strlen(rule_line_token));
                    break;
            case 1: if(!strncmp(rule_line_token, "in", strlen("in"))) {
                        direction = DIRECTION_IN;
                    }
                    else if(!strncmp(rule_line_token, "out", strlen("out"))) {
                        direction = DIRECTION_OUT;
                    }
                    else {
                        direction = DIRECTION_ANY;
                    }
                    strncpy(rule_ptr->direction, direction, sizeof(rule_t));
                    break;
            case 2: if (!strncmp(rule_line_token, "any", strlen("any"))) {
                        strncpy(rule_ptr->src_ip, 0, sizeof(unsigned int));
                    }
                    ip_token = strtok(rule_line_token, "/");
                    be_ip_number = make_be_ip_number(ip_token);
                    strncpy(rule_ptr->src_ip, be_ip_number, sizeof(unsigned int));
                    mask_token = strtok(NULL, "/");
                    strncpy(rule_ptr->src_prefix_mask, atoi(mask_token), sizeof(unsigned int));
                    strncpy(rule_ptr->src_prefix_size, atoi(mask_token), sizeof(unsigned char));

                    break;
            case 3: if (strncmp(rule_line_token, "any", strlen("any"))) {
                            ip_token = strtok(rule_line_token, "/");
                            validate_ip(ip_token);
                            ip_token = strtok(NULL, "/");
                            validate_mask(ip_token);
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

// show firewall rules
// through reading
// from /sys/class/fw/rules/rules
void show_rules(void)
{
    int i;
    FILE *show_fw_rules_fp;
    // TODO: fix this to the real size of the rule structure from fw.h
    unsigned int RULE_SIZE = 100;
    // TODO: fix this to the real log structure from fw.h
    char rule_buffer[100];

    show_fw_rules_fp = fopen(RULES_ATTR_PATH, "r");

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
    FILE *fw_logs_fp;
    // TODO: fix this to the real size of the log structure from fw.h
    unsigned int PACKET_LOG_SIZE = 100;
    // TODO: fix this to the real log structure from fw.h
    char log_buffer[100];

    fw_logs_fp = fopen(FW_LOG_DEVICE, "r");

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
    FILE *fw_logs_reset_fp;
    FILE *fw_logs_clear_fp;

    // deallocate the log resources
    fw_logs_reset_fp = fopen(RESET_ATTR_PATH, "w");
    write(fw_logs_reset_fp, "0", strlen("0"));
    close(fw_logs_reset_fp);

    // clear the file from the logs using the write flag
    fw_logs_clear_fp = fopen(FW_LOG_DEVICE, "w");
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