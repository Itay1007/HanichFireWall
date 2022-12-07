FIREWALL_TABLE_COLMUNS_NUM = 9

def validate_user_input(argc, argv):
    if argc == 3 and argv[2] == "load_rules":
        return
    
    if argc == 2 and argv[1] in ["show_rules", "show_log", "clear_log"]:
        return

    print("Usage: ./main.py [show_rules/show_log/clear_log] or\n./main.py load_rules <path_to_rules_file>")
    exit(0)

def validate_rules_file_line(rule_line):
    rule_line_tokens = rule_line.split()
    if len(rule_line_tokens) != FIREWALL_TABLE_COLMUNS_NUM:
        print(f"File contains invalid number of columns in a line. No {FIREWALL_TABLE_COLMUNS_NUM}")
        exit(0)

    validate_rule_name(rule_line_tokens[0])
    validate_direction(rule_line_tokens[1])
    if rule_line_tokens[2] != "any":
        source_ip, mask = rule_line_tokens[2].split("/")
        validate_ip(source_ip)
        validate_mask(mask)

    if rule_line_tokens[3] != "any":
        dest_ip, mask = rule_line_tokens[3].split("/")
        validate_ip(dest_ip)
        validate_mask(mask)
    validate_protocol(rule_line_tokens[4])
    validate_port(rule_line_tokens[5])
    validate_port(rule_line_tokens[6])
    validate_ack(rule_line_tokens[7])
    validate_action(rule_line_tokens[8])

def validate_rule_name(rule_name):
    if len(rule_name) > 20:
        print(f"Rule Name should be at most 20 characters long. Invalid rule name: {rule_name}")
        exit(0)

def validate_direction(direction):
    if direction not in ["in", "out", "any"]:
        print(f"Direction field in rule table is from ['in', 'out', 'any']. Invalid given direction {direction}")
        exit(0)

def validate_ip(ip):
    ip_octets = ip.split(".")
    if len(ip_octets) != 4:
        print(f"Invalid source ip {ip}")
        exit(0)

    for ip_octet in ip_octets:
        if int(ip_octet) < 0 or 255 < int(ip_octet):
            print(f"Invalid ip octet: {ip_octet}")
            exit(0)

def validate_mask(mask):
    if int(mask) < 0 or 31 < int(mask):
        print(f"Invalid mask {mask}. Should be int from [0, 31]")
        exit(0)

def validate_protocol(protocol_name):
    if protocol_name not in ["TCP", "UDP", "ICMP", "any"]:
        print(f"Invalid protocol name {protocol_name}. Not in ['TCP', 'UDP', 'ICMP', 'any']")
        exit(0)

def validate_port(port):
    try:
        if (0 <= int(port) <= 1023) or (port[0] == ">" and int(port[1:]) == 1023):
            return
    except:
        print(f"Invalid port {port}")
        exit(0)

    print(f"Invalid port {port}")
    exit(0)

def validate_ack(ack):
    if ack not in ["yes", "no", "any"]:
        print(f"Invalid ack {ack}. Not in ['yes', 'no', 'any']")
        exit(0)

def validate_action(action):
    if action not in ["accept", "drop"]:
        print(f"Invaild action. Not in ['accept', 'drop']")
        exit(0)
