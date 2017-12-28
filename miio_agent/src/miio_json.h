#ifndef __MIIO_JSON_H
#define __MIIO_JSON_H

enum json_type;

int json_verify(char *string);
int json_verify_method(char *string, char *method);
int json_verify_method_value(char *string, char *method, void *value, enum json_type type);
int json_verify_get_int(char *string, char *key, int *value);
#endif
