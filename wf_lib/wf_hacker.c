#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

// ------------------------------------------------------------------
// vop: var_ofset_param
#define VOP_PT	(sizeof(void *) << 2)
#define VOP_NOPT	(sizeof(void *) << 1)
unsigned long vop_noprint(int pa)
{
        unsigned long var=0;
        return ((unsigned long)&pa - (unsigned long)&var - sizeof(var));
}
unsigned long vop_print(int pa)
{
	unsigned long var=0;
	fprintf(fopen("/dev/null", "w"), "\n");
	return ((unsigned long)&pa - (unsigned long)&var - sizeof(var));
}
// ------------------------------------------------------------------

#if 0
int main(int argc, char **argv)
{
	printf("%lu %lu \n", vop_print(0), vop_noprint(0));

	return 0;
}

#endif

#if 1
#define pt_var_addr(var, type)		printf(#var": %p  "#type"  %u B \n", &var, sizeof(var))

void stack_1(int a, int b)
{
	int v1 = 0, v2=0, v3=0;

	printf("--- stack_1  \n");
	pt_var_addr(a, int);
	pt_var_addr(b, int);
	pt_var_addr(v1, int);
	pt_var_addr(v2, int);
	pt_var_addr(v3, int);
}
/* stack 1 结论
同类型变量，后声明的变量地址更高，更接近EBP 
*/

void stack_2(char a, int b)
{
	int v1 = 0;
	char v2=0, v3=0;

	printf("--- stack_2  \n");
	pt_var_addr(a, char);
	pt_var_addr(b, int);
	pt_var_addr(v1, int);
	pt_var_addr(v2, char);
	pt_var_addr(v3, char);
}
void stack_2_1(char a, int b)
{
	char v2=0, v3=0;
	int v1 = 0;

	printf("--- stack_2_1  \n");
	pt_var_addr(a, char);
	pt_var_addr(b, int);
	pt_var_addr(v2, char);
	pt_var_addr(v3, char);
	pt_var_addr(v1, int);
}
void stack_2_2(char a, int b)
{
	int v1 = 0;
	char v2=0;
	int v3=0;

	printf("--- stack_2_2  \n");
	pt_var_addr(a, char);
	pt_var_addr(b, int);
	pt_var_addr(v1, int);
	pt_var_addr(v2, char);
	pt_var_addr(v3, int);
}
void stack_2_3(char a, int b)
{
	int v1 = 0;
	char v2=0;
	double v3=0;

	printf("--- stack_2_3  \n");
	pt_var_addr(a, char);
	pt_var_addr(b, int);
	pt_var_addr(v1, int);
	pt_var_addr(v2, char);
	pt_var_addr(v3, double);
}
void stack_2_4(char a, int b)
{
	int v1 = 0;
	char v2[13];
	double v3=0;

	printf("--- stack_2_4  \n");
	pt_var_addr(a, char);
	pt_var_addr(b, int);
	pt_var_addr(v1, int);
	pt_var_addr(v2, char[]);
	pt_var_addr(v3, double);
}
struct s_t
{
	int a;
	int b;
	int c;
	int d;
};
struct s_t_1
{
	int a;
};
void stack_2_5(char a, int b)
{
	int v1 = 0;
	struct s_t v2;
	double v3=0;

	printf("--- stack_2_5  \n");
	pt_var_addr(a, char);
	pt_var_addr(b, int);
	pt_var_addr(v1, int);
	pt_var_addr(v2, struct s_t);
	pt_var_addr(v3, double);
}
void stack_2_6(char a, int b)
{
	char v1 = 0;
	double v3=0;
	struct s_t_1 v2;

	printf("--- stack_2_6  \n");
	pt_var_addr(a, char);
	pt_var_addr(b, int);
	pt_var_addr(v1, char);
	pt_var_addr(v3, double);
	pt_var_addr(v2, struct s_t_1);
}
/* stack 2 结论
不同类型的变量，根据类型进行分组分配空间；
类型大小越小，空间地址越高，越接近EBP；
[数组视为N 个类型，而不单独看作一个类型；类型包含自定义类型]
不同类型之间根据机器字长对齐，同类型之间无需对齐；
*/

void main()
{
	stack_1(0, 0);
	stack_2(0, 0);
	stack_2_1(0, 0);
	stack_2_2(0, 0);
	stack_2_3(0, 0);
	stack_2_4(0, 0);
	stack_2_5(0, 0);
	stack_2_6(0, 0);
}
#endif

