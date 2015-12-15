#ifndef WF_KV_H_
#define WF_KV_H_

extern int wf_put_kv(void *key, unsigned int key_size, void *value, unsigned int value_size);

extern int wf_get_kv(void *key, unsigned int key_size, void *value, unsigned int value_size);

extern int wf_replace_kv(void *key, unsigned int key_size, void *value, unsigned int value_size);

extern int wf_del_kv(void *key, unsigned int key_size);

#define wf_string_put_kv(key, value)	wf_put_kv(key, strlen(key), value, strlen(value))
#define wf_string_get_kv(key, value, value_size)	wf_get_kv(key, strlen(key), value, value_size)
#define wf_string_replace_kv(key, value)	wf_replace_kv(key, strlen(key), value, strlen(value))
#define wf_string_del_kv(key)	wf_del_kv(key, strlen(key))

#endif

