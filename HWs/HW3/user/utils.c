#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

unsigned int make_be_ip_number(char * ip) {
    unsigned char ip_octets[4];
    char *ip_octet;
    int i;
    unsigned int be_ip_number;

    ip_octet = strtok(ip, ".");
    while(ip_octet != NULL) {
        ip_octets[i] = atoi(ip_octet);
        i++;
        ip_octet = strtok(NULL, ".");
    }

    for(i = 0; i < 4; i ++) {
        be_ip_number += ip_octets[i] * pow(256, i); 
    }
    return be_ip_number;
}

unsigned int make_network_mask_size_ip_be_number(unsigned int network_mask_size)
{
    int i = 0;
    unsigned int build_be_network_mask_ip_be_number;

    if(network_mask_size == 0) {
        return build_be_network_mask_ip_be_number;
    }

    build_be_network_mask_ip_be_number += 1;
    for(i = 0; i < network_mask_size - 1; i ++) {
        build_be_network_mask_ip_be_number << 1;
        build_be_network_mask_ip_be_number += 1;
    }

    return build_be_network_mask_ip_be_number;
}