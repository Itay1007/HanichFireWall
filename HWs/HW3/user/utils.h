#ifndef _UTILS_H_
#define _UTILS_H_

#define NF_DROP 0
#define NF_ACCEPT 1

// the protocols we will work with
typedef enum {
	PROT_ICMP	= 1,
	PROT_TCP	= 6,
	PROT_UDP	= 17,
	PROT_OTHER 	= 255,
	PROT_ANY	= 143,
} prot_t;


// various reasons to be registered in each log entry
typedef enum {
	REASON_FW_INACTIVE           = -1,
	REASON_NO_MATCHING_RULE      = -2,
	REASON_XMAS_PACKET           = -4,
	REASON_ILLEGAL_VALUE         = -6,
} reason_t;

// auxiliary values, for your convenience
#define IP_VERSION		(4)
#define PORT_ANY		(0)
#define PORT_ABOVE_1023	(1023)
#define MAX_RULES		(50)

// device minor numbers, for your convenience
typedef enum {
	MINOR_RULES    = 0,
	MINOR_LOG      = 1,
} minor_t;

typedef enum {
	ACK_NO 		= 0x01,
	ACK_YES 	= 0x02,
	ACK_ANY 	= ACK_NO | ACK_YES,
} ack_t;

typedef enum {
	DIRECTION_IN 	= 0x01,
	DIRECTION_OUT 	= 0x02,
	DIRECTION_ANY 	= DIRECTION_IN | DIRECTION_OUT,
} direction_t;

// rule base
typedef struct {
	char 			rule_name[20];			// names will be no longer than 20 chars
	direction_t 	direction;
	unsigned int    src_ip;
	unsigned int	src_prefix_mask; 	// e.g., 255.255.255.0 as int in the local endianness
	unsigned char   src_prefix_size; 	// valid values: 0-32, e.g., /24 for the example above
								// (the field is redundant - easier to print)
	unsigned int	dst_ip;
	unsigned int	dst_prefix_mask; 	// as above
	unsigned char   dst_prefix_size; 	// as above	
	unsigned short	src_port; 			// number of port or 0 for any or port 1023 for any port number > 1023  
	unsigned short	dst_port; 			// number of port or 0 for any or port 1023 for any port number > 1023 
	unsigned char	protocol; 			// values from: prot_t
	ack_t			ack; 				// values from: ack_t
	unsigned char	action;   			// valid values: NF_ACCEPT, NF_DROP
} rule_t;

// logging
typedef struct {
	unsigned long  	timestamp;     	// time of creation/update
	unsigned char  	protocol;     	// values from: prot_t
	unsigned char  	action;       	// valid values: NF_ACCEPT, NF_DROP
	unsigned int   	src_ip;		  	// if you use this struct in userspace, change the type to unsigned int
	unsigned int	dst_ip;		  	// if you use this struct in userspace, change the type to unsigned int
	unsigned short 	src_port;	  	// if you use this struct in userspace, change the type to unsigned short
	unsigned short 	dst_port;	  	// if you use this struct in userspace, change the type to unsigned short
	reason_t     	reason;       	// rule#index, or values from: reason_t
	unsigned int   	count;        	// counts this line's hits
} log_row_t;

unsigned int make_be_ip_number(char * ip);
unsigned int make_network_mask_size_ip_be_number(unsigned int network_mask_size);
void fill_ip_mask(char *ip, char *mask, char *rule_line_token);
void parse_line_to_rule(rule_t *rule_ptr, char* rule_chars_line);
void print_rule(rule_t *rule_ptr);
void print_rule_in_format(rule_t *rule_ptr);

#endif // _UTILS_H_