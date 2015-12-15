#include <stdio.h>

#include "wf_bit.h"

//-----  参考内核asm/bitops.h 中的原子位操作
//-----  去除了原子性，仅有位操作

#define BITS_PER_LONG	(sizeof(long) * 8)
#define BIT(nr)			(1UL << (nr))
#define BIT_MASK(nr)		(1UL << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr)		((nr) / BITS_PER_LONG)

/**
 * set_bit - Atomically set a bit in memory
 * @nr: the bit to set
 * @addr: the address to start counting from
 */
inline void set_bit(int nr, unsigned long *addr)
{
	unsigned long mask = BIT_MASK(nr);
	unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);

	*p  |= mask;
}
/**
 * clear_bit - Clears a bit in memory
 * @nr: Bit to clear
 * @addr: Address to start counting from
 */
inline void clear_bit(int nr, unsigned long *addr)
{
	unsigned long mask = BIT_MASK(nr);
	unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);
	
	*p &= ~mask;
}
/**
 * change_bit - Toggle a bit in memory
 * @nr: Bit to change
 * @addr: Address to start counting from
 */
inline void change_bit(int nr, unsigned long *addr)
{
	unsigned long mask = BIT_MASK(nr);
	unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);

	*p ^= mask;
}
/**
 * test_and_set_bit - Set a bit and return its old value
 * @nr: Bit to set
 * @addr: Address to count from
 */
inline int test_and_set_bit(int nr, unsigned long *addr)
{
	unsigned long mask = BIT_MASK(nr);
	unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);
	unsigned long old;

	old = *p;
	*p = old | mask;

	return (old & mask) != 0;
}
/**
 * test_and_clear_bit - Clear a bit and return its old value
 * @nr: Bit to clear
 * @addr: Address to count from
 */
inline int test_and_clear_bit(int nr, unsigned long *addr)
{
	unsigned long mask = BIT_MASK(nr);
	unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);
	unsigned long old;

	old = *p;
	*p = old & ~mask;

	return (old & mask) != 0;
}
/**
 * test_and_change_bit - Change a bit and return its old value
 * @nr: Bit to change
 * @addr: Address to count from
 */
inline int test_and_change_bit(int nr, unsigned long *addr)
{
	unsigned long mask = BIT_MASK(nr);
	unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);
	unsigned long old;

	old = *p;
	*p = old ^ mask;

	return (old & mask) != 0;
}

inline int test_bit(int nr, const unsigned long *addr)
{
	unsigned long mask = BIT_MASK(nr);
	unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);

	return (*p & mask) != 0;
}

/**
 * find_next_bit - find the next set bit in a memory region
 * @addr: The address to base the search on
 * @offset: The bitnumber to start searching at
 * @size: The bitmap size in bits
 */
unsigned int find_next_bit(const unsigned long *addr, unsigned int size, unsigned int offset)
{
	unsigned int nr;
	for(nr = offset; nr < size; nr++)
	{
		if( test_bit(nr, addr) )
			return nr;
	}
	return size;
}

/**
 * find_next_zero_bit - find the next cleared bit in a memory region
 * @addr: The address to base the search on
 * @offset: The bitnumber to start searching at
 * @size: The bitmap size in bits
 */
unsigned int find_next_zero_bit(const unsigned long *addr, unsigned int size, unsigned int offset)
{
	unsigned int nr;
	for(nr = offset; nr < size; nr++)
	{
		if( !test_bit(nr, addr) )
			return nr;
	}
	return size;
}

#if 0
int main()
{
	unsigned long a = 0;
	int b=0;
	set_bit(3, &a);
	b= find_first_bit(&a, sizeof(a));

	printf("%p %d\n", (void *)a, b);
	
	return 0;
}
#endif

