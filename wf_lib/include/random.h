#ifndef RANDOM_H_
#define RANDOM_H_

extern int get_dev_urandom(void *data, int dlen);

extern int get_random_num(int max);

extern int get_random_key_bin(void *key, int key_len);

extern int get_random_key_str(char *key, int key_len);

#endif

