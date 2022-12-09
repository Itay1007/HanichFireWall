#ifndef _UTILS_H_
#define _UTILS_H_

unsigned int make_be_ip_number(char * ip);
unsigned int make_network_mask_size_ip_be_number(unsigned int network_mask_size);
void fill_ip_mask(char *ip_ptr[20], char *mask_prt[3], char *rule_line_token);

#endif // _UTILS_H_