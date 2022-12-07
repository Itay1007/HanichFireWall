import sys
import socket
import struct

from validation import *
FIREWALL_TABLE_COLMUNS_NUM = 9

# User space program that will communicate with the kernel module.
# The program get an arguments and work by them.
# The supported values are:
# •	show_rules
# •	load_rules <path_to_rules_file>
# •	show_log
# •	clear_log


# load firewall rules
# through writing
# to /sys/class/fw/rules/rules
def load_rules(path_to_rules_file):
    rules_file_fw = open(path_to_rules_file, "r")
    rules_lines = rules_file_fw.readlines()
    fw_rules_fd = open("/sys/class/fw/rules/rules", "w")
    for rule_line in rules_lines:
        validate_rules_file_line(rule_line)
        parsed_rule_line = get_parsed_rule_line(rule_line)
        fw_rules_fd.write(parsed_rule_line)
    fw_rules_fd.close()

def get_parsed_rule_line(rule_line):
    direction_mapping = {"in": "1", "out": "2", "any": "3"}
    protocol_mapping = {"ICMP": "1", "TCP": "6", "UDP": "17", "any": "143"}
    ack_mapping = {"no": "0", "yes": "1", "any": "2"}
    action_mapping = {"drop": "0", "accept": "1"}

    # get fields from rule line
    rule_line_tokens = rule_line.split()
    parsed_rule_line_tokens = []

    rule_name = rule_line_tokens[0]
    parsed_rule_line_tokens.append(rule_name)
    
    direction = rule_line_tokens[1]
    parsed_rule_line_tokens.append(direction_mapping[direction])
    
    source_ip,  source_network_mask = rule_line_tokens[2].split("/")
    parsed_rule_line_tokens.append(ip_into_be_num(source_ip))
    parsed_rule_line_tokens.append(source_network_mask)

    dest_ip, dest_network_mask = rule_line_tokens[3].split("/")
    parsed_rule_line_tokens.append(ip_into_be_num(dest_ip))
    parsed_rule_line_tokens.append(dest_network_mask)

    protocol = rule_line_tokens[4]
    parsed_rule_line_tokens.append(protocol_mapping[protocol])

    source_port = rule_line_tokens[5]
    source_port_parsed = source_port if source_port != ">1023" else "1023"
    parsed_rule_line_tokens.append(source_port_parsed)
    
    dest_port = rule_line_tokens[6]
    dest_port_parsed = dest_port if dest_port != ">1023" else "1023"
    parsed_rule_line_tokens.append(dest_port_parsed)
    
    ack = rule_line_tokens[7]
    parsed_rule_line_tokens.append(ack_mapping[ack])

    action = rule_line_tokens[8]
    parsed_rule_line_tokens.append(action_mapping[action])

    parsed_rule_line_tokens = list(map(lambda field_value: str(field_value), parsed_rule_line_tokens))
    return " ".join(parsed_rule_line_tokens)

def ip_into_be_num(ip):
    packedIP = socket.inet_aton(ip)
    return struct.unpack("<L", packedIP)[0]

# show firewall rules
# through reading
# from /sys/class/fw/rules/rules
def show_rules():
    show_fw_rules_fd = open("/sys/class/fw/rules/rules", "r")
    show_fw_rules_fd.read()
    show_fw_rules_fd.close()

# show firewall logs
# through reading
# from /dev/fw_log
def show_log():
    fw_logs_fd = open("/dev/fw_log", "r")
    fw_logs_fd.read()
    fw_logs_fd.close()

# clear firewall logs
# through writing anything (N/A)
# to /sys/class/fw/log/reset
def clear_log():
    fw_logs_reset_fd = open("/sys/class/fw/log/reset", "w")
    fw_logs_reset_fd.write("0")
    fw_logs_reset_fd.close()

    fw_logs_clear_fd = open("/dev/fw_log", "w")
    fw_logs_clear_fd.truncate()
    fw_logs_clear_fd.close()

def main(argc, argv):
    validate_user_input(argc, argv)
    perform_load = (argc == 3) and argv[1] == "load_rules"
    if perform_load:
        load_rules(argv[2])
    elif argv[1] == "show_rules":
        show_rules()
    elif argv[1] == "show_log":
        show_log()
    elif argv[1] == "clear_log":
        clear_log()


if __name__ == "__main__":
    main(len(sys.argv), sys.argv)