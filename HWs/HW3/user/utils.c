#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"

unsigned int make_be_ip_number(char *ip) {
    char ip_octets[4][3];
    char *ip_octet;
    int i, j, k;
    unsigned int be_ip_number;

    for(i = 0, j = 0, k = 0; ip[i]; i++) {
        if(ip[i] == '.') {
            ip_octets[j][k] = '\0';
            j++;
            k = 0;
        }
        else {
            ip_octets[j][k] = ip[i];
            k++;
        }
    }

    be_ip_number = 0;
    for(j = 0; j < 4; j++) {
        be_ip_number += atoi(ip_octets[j]) * pow(256, j); 
    }
    return be_ip_number;
}

unsigned int make_network_mask_size_ip_be_number(unsigned int network_mask_size)
{
    int i = 0, full_octets_number = 0, bits_in_partial_octet_number;
    unsigned int build_be_network_mask_ip_be_number = 0;

    if(network_mask_size == 0) {
        return build_be_network_mask_ip_be_number;
    }

    full_octets_number = network_mask_size / 8;
    for(i = 0; i < full_octets_number; i++) {
        build_be_network_mask_ip_be_number += 255 * pow(256, i);
    }

    bits_in_partial_octet_number = network_mask_size % 8;
    for(i = 0; i < bits_in_partial_octet_number; i++) {
        build_be_network_mask_ip_be_number += pow(256, full_octets_number) * pow(2, 7 - i);
    }

    return build_be_network_mask_ip_be_number;
}

void fill_ip_mask(char *ip, char *mask, char *rule_line_token) {
    int i;
    int j;
    char sep = '/';

    for(i = 0, j = 0; rule_line_token[i] != sep; i++, j++) {
        ip[j] = rule_line_token[i];
    }
    ip[j] = '\0';

    for(i++, j = 0 ; rule_line_token[i] && j < 2; i++, j++)
    {
        mask[j] = rule_line_token[i]; 
    }
    mask[j] = '\0';
}

void parse_line_to_rule(rule_t *rule_ptr, char* rule_chars_line) {
    int i = 0, j = 0;
    int rule_element_i = 0;
    char rule_line_token[20];
    char ip[20];
    char mask[3];
    unsigned int be_ip_number;
    unsigned char mask_size;

    for(rule_element_i = 0; rule_element_i < 9; rule_element_i) {
        for(; rule_chars_line[i] == ' ' || rule_chars_line[i] == '\0' || rule_chars_line[i] == '\n'; i++) {
        }

        for(j = 0; rule_chars_line[i] != ' ' && rule_chars_line[i] != '\0' && rule_chars_line[i] != '\n'; i++, j++) {
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
                        rule_ptr->direction = DIRECTION_IN;
                    }
                    else if(!strncmp(rule_line_token, "out", strlen("out"))) {
                        rule_ptr->direction = DIRECTION_OUT;
                    }
                    else {
                        rule_ptr->direction = DIRECTION_ANY;
                    }
                    break;
            case 2: if (!strncmp(rule_line_token, "any", strlen("any"))) {
                        rule_ptr->src_ip = 0;
                        break;
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
                        break;
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

void print_rule(rule_t *rule_ptr) {
        printf("Data of a rule:\n");
        printf("rule name: %s\n", rule_ptr->rule_name);
        printf("direction: %d\n", rule_ptr->direction);
        printf("source sample network ip address: %d\n", rule_ptr->src_ip);
        printf("source mask number in be: %d\n", rule_ptr->src_prefix_mask);
        printf("dest mask size: %d\n", rule_ptr->src_prefix_size);
        printf("dest sample network ip address: %d\n", rule_ptr->dst_ip);
        printf("dest mask number in be: %d\n", rule_ptr->dst_prefix_mask);
        printf("dest mask size: %d\n", rule_ptr->dst_prefix_size);
        printf("protocol number: %d\n", rule_ptr->protocol);
        printf("source port: %d\n", rule_ptr->src_port);
        printf("dest port: %d\n", rule_ptr->dst_port);
        printf("ack: %d\n", rule_ptr->ack);
        printf("action: %d\n", rule_ptr->action);
}

void print_rule_in_format(rule_t *rule_ptr) {
    int i = 0, j = 0;
    int rule_element_i = 0;
    char rule_line_token[20];
    char ip[20];
    char mask[3];
    unsigned int be_ip_number;
    unsigned char mask_size;

    for(rule_element_i = 0; rule_element_i < 9; rule_element_i) {
        switch(rule_element_i) {
            case 0: printf("%s", rule_ptr->rule_name);
                    printf(" ");
                    break;
            case 1: print_direction(rule_ptr->direction);
                    printf(" ");
                    break;
            case 2: 
                    break;
            case 3:
                    break;
            case 4: print_protocol(rule_ptr->protocol);
                    printf(" ");
                    break;
            case 5: print_port(rule_ptr->src_port);
                    printf(" ");
                    break;
            case 6: print_port(rule_ptr->dst_port);
                    printf(" ");
                    break;
            case 7: print_ack(rule_ptr->ack);
                    printf(" ");
                    break;
            case 8: print_action(rule_ptr->action);
                    printf(" ");
                    break;
            default:
                    printf("File contains invalid number of columns in a line. No {FIREWALL_TABLE_COLMUNS_NUM}\n");
                    exit(0);
        }
        rule_element_i++;
    }
}

void print_direction(direction_t direction) {
    if(direction == DIRECTION_IN){
        printf("in");
    }
    else if(direction == DIRECTION_OUT){
        printf("out");
    }
    else if(direction == DIRECTION_ANY){
        printf("any");
    }
}

void print_protocol(prot_t protocol) {
        if(protocol == PROT_TCP) {
            printf("tcp");
        }
        else if (protocol == PROT_UDP) {
            printf("udp");
        }
        else if(protocol == PROT_ICMP) {
            printf("icmp");
        }
        else if(protocol == PROT_ANY){
            printf("any");
        }
}

void print_ack(ack_t ack) {
    if(ack == ACK_YES) {
        printf("yes");
    }
    else if(ack == ACK_YES) {
        printf("no");
    }
    else {
        printf("any");
    }
}

void print_action(unsigned char action) {
    if(action == NF_ACCEPT) {
        printf("accept");
    }
    else {
        printf("drop");
    }
}

void print_port(unsigned short port) {
    char char_array_port[4];
    if(port == 0) {
        printf("any");
    }
    else if(port == 1023) {
        printf(">1023");
    }
    else {
        snprintf(char_array_port, 4, "%d", port);
        printf("%s", char_array_port);
    }
}

void print_network_ip_sample(unsigned int ip) {
    if(ip == 0) {
        printf("any");
    }
    else {

    }

}