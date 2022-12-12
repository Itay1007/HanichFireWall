#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include "main.h"

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
    int i = 0;

    printf("User space load rules\n");

    firewall_new_rules_file_fp = fopen(path_to_rules_file, "r");
    firewall_update_rules_fp = open(RULES_ATTR_PATH, O_WRONLY);

    while(fgets(rule_chars_line, 500, firewall_new_rules_file_fp)) {
        validate_rules_file_line(rule_chars_line);
        parse_line_to_rule(&rule, rule_chars_line);
        print_rule(&rule);
        // printf("print user space chars of the rule load rules:\n");
        // for(i = 0; i < 60; i++) {
        //     printf("%i-%c-%d\t", i, ((char *)&rule)[i], ((char *)&rule)[i]);
        // }
        write(firewall_update_rules_fp, &rule, sizeof(rule));
    }

    fclose(firewall_new_rules_file_fp);
    close(firewall_update_rules_fp);
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
    // rule_t static_rules_table[MAX_RULES];
    rule_t rule;
    char *char_ptr_rule = (char *) &rule;

    printf("User space show rules\n");

    show_fw_rules_fp = open(RULES_ATTR_PATH, O_RDONLY);

    read(show_fw_rules_fp, char_ptr_rule, RULE_SIZE);

    print_rule_in_format(&rule);

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

    printf("User space show log\n");

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

    printf("User space clear log\n");

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