#ifndef WF_BIT_H_
#define WF_BIT_H_

// 不支持原子操作，对于共享数据，需要考虑互斥

extern inline void set_bit(int nr, unsigned long *addr);

extern inline void clear_bit(int nr, unsigned long *addr);

extern inline void change_bit(int nr, unsigned long *addr);

extern inline int test_and_set_bit(int nr, unsigned long *addr);

extern inline int test_and_clear_bit(int nr, unsigned long *addr);

extern inline int test_and_change_bit(int nr, unsigned long *addr);

extern inline int test_bit(int nr, const unsigned long *addr);

extern unsigned int find_next_bit(const unsigned long *addr, unsigned int size, unsigned int offset);

extern unsigned int find_next_zero_bit(const unsigned long *addr, unsigned int size, unsigned int offset);


#define find_first_bit(addr, size) find_next_bit((addr), (size), 0)
#define find_first_zero_bit(addr, size) find_next_zero_bit((addr), (size), 0)

#define for_each_set_bit(bit, addr, size) \
	for ((bit) = find_first_bit((addr), (size)); \
	     (bit) < (size); \
	     (bit) = find_next_bit((addr), (size), (bit) + 1))

#endif
