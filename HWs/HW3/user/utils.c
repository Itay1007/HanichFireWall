#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

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