#ifndef WF_TREE_H_
#define WF_TREE_H_

struct rbtree
{
	struct rbtree *left;
	struct rbtree *right;
	struct rbtree *parent;
	struct rbtree *brother;
	unsigned char color;				// 0x00: red     0xFF: black
};

struct rbtree_root
{
	struct rbtree *leaf_parent;			// 叶子的父节点
	struct rbtree *root;
	unsigned int num;
};


#define INIT_RBTREE(ptr)	memset(ptr, 0, sizeof(struct rbtree))

#define INIT_RBTREE_ROOT(root)	memset(root, 0, sizeof(struct rbtree_root))

#define RBTREE_ROOT(name)	do { \
	struct rbtree_root name; \
	INIT_RBTREE_ROOT(name); \
} while (0)

#define rbtree_entry(ptr, type, member) \
	((type *)((char *)(ptr)-(unsigned long)(&((type *)0)->member)))


extern void insert_rbnode(struct rbtree_root *tree, struct rbtree *node);

typedef void (*RB_CALL)(struct rbtree *ptr, void *data, unsigned int size);

// 中序遍历
extern void rbtree_inorder_traversal(struct rbtree *root, RB_CALL call, void *data, unsigned int size);

// 后序遍历
extern void rbtree_postorder_traversal(struct rbtree *root, RB_CALL call, void *data, unsigned int size);

// 先序遍历
extern void rbtree_preorder_traversal(struct rbtree *root, RB_CALL call, void *data, unsigned int size);

#endif
