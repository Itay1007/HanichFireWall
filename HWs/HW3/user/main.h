#ifndef _MAIN_H_
#define _MAIN_H_

#include "validation.h"
#include "utils.h"

void load_rules(char *path_to_rules_file);
void parse_line_to_rule(rule_t *rule_ptr, char* rule_chars_line);
void show_rules(void);
void show_log(void);
void clear_log(void);

#endif // _MAIN_H_