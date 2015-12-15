#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wf_tree.h"

struct btree
{
	struct rbtree *left;
	struct rbtree *right;
	struct rbtree *parent;
	struct rbtree *brother;
};


/*
性质
1）每个结点要么是红的，要么是黑的。
2）根结点是黑的。
3）每个叶结点，即空结点（NIL）是黑的。
4）如果一个结点是红的，那么它的俩个儿子都是黑的。
5）对每个结点，从该结点到其子孙结点的所有路径上包含相同数目的黑结点。

插入  insert
1、根红，则根反
2、父、叔红祖必黑，则父、叔、祖反，指祖检 1
3、父红叔黑祖必黑，父左子左，则父、祖反，祖右旋
4、父红叔黑祖必黑，父左子右，则父左旋，指原父检 3
5、父红叔黑祖必黑，父右子右，则父、祖反，祖左旋
6、父红叔黑祖必黑，父右子左，则父右旋，指原父检 5
7、父黑，则不动
8、根黑，则不动

移除	remove
如果target 节点只有一个或没有孩子，可直接对它进行删除操作；
如果target 节点有两个孩子，则需要在target  子树中寻找替代点，
替代点为target 的前继节点或后继节点，
前继节点必定没有右孩子，后继节点必定没有左孩子；
*/

#define RB_DEBUG	1

#define RED		0x00
#define BLACK	0xFF

#define rb_turn_color(node)	(node)->color = ~((node)->color)

#if RB_DEBUG
static void print_rbtree(struct rbtree *root, int zero)
{
	static char str[10][100];
	static int n = 0;
	int i=0;
	
	if(zero > n)	n = zero;
	if(zero == 0)	memset(str, 0, sizeof(str));

	if(root == NULL)
	{
		strcat(str[zero], "N ");
	}
	else
	{
		strcat(str[zero], (root->color) ? "B " : "R ");
	}
	
	if(root == NULL)
		return;
	
	print_rbtree(root->left, zero+1);
	print_rbtree(root->right, zero+1);

	if(zero == 0)
	{
		printf("------ \n");
		for(i=0; i<=n; i++)
		{
			printf("%s \n", str[i]);
		}
	}
}
#endif

static void left_rotate(struct rbtree_root *tree, struct rbtree *node)
{
	struct rbtree *nchild = node->right;	// != NULL

	if(node == tree->root)
		tree->root = nchild;
	
	else if(node == node->parent->left)
		node->parent->left = nchild;
	else
		node->parent->right = nchild;

	if(node->left)
		node->left->brother = nchild->left;
	if(nchild->left)
		nchild->left->brother = node->left;
	if(nchild->right)
		nchild->right->brother = node;
	nchild->brother = node->brother;
	node->brother = nchild->right; 
	
	nchild->parent = node->parent;
	node->right = nchild->left;
	if(nchild->left != NULL)		node->right->parent = node;
	nchild->left = node;
	node->parent = nchild;
}

static void right_rotate(struct rbtree_root *tree, struct rbtree *node)
{
	struct rbtree *nchild = node->left;		// != NULL

	if(node == tree->root)
		tree->root = nchild;
	
	else if(node == node->parent->left)
		node->parent->left = nchild;
	else
		node->parent->right = nchild;

	if(node->right)
		node->right->brother = nchild->right;
	if(nchild->left)
		nchild->left->brother = node;
	if(nchild->right)
		nchild->right->brother = node->right;
	nchild->brother = node->brother;
	node->brother = nchild->left; 

	nchild->parent = node->parent;
	node->left = nchild->right;
	if(nchild->right != NULL)	node->left->parent = node;
	nchild->right = node;
	node->parent = nchild;
}

static void exchange_rbtree(struct rbtree_root *tree, struct rbtree *m, struct rbtree *n)
{
	struct rbtree *l, *r, *p, *b, *ml, *mr, *mp, *mb, *nl, *nr, *np, *nb;
	unsigned char c;
		
	if(tree == NULL || m == NULL || n == NULL)
	{
		#if RB_DEBUG
		printf("exchange_rbtree: nothing \n");
		#endif
		
		return;
	}

	ml = m->left;
	mr = m->right;
	mp = m->parent;
	mb = m->brother;

	nl = n->left;
	nr = n->right;
	np = n->parent;
	nb = n->brother;

	l = m->left;
	r = m->right;
	p = m->parent;
	b = m->brother;
	c = m->color;

	m->left = n->left;
	m->right = n->right;
	m->parent = n->parent;
	m->brother = n->brother;
	m->color = n->color;

	n->left = l;
	n->right = r;
	n->parent = p;
	n->brother = b;
	n->color = c;

	if(ml)	ml->parent = n;
	if(mr)	mr->parent = n;
	if(mb)	mb->brother = n;
	if(mp)
	{
		if(mp->left == m)		mp->left = n;
		else					mp->right = n;
	}
	
	if(nl)	nl->parent = m;
	if(nr)	nr->parent = m;
	if(nb)	nb->brother = m;
	if(np)
	{
		if(np->left == n)		np->left = m;
		else					np->right = m;
	}

	if(tree->root == m)		tree->root = n;
	else if(tree->root == n)	tree->root = m;
	else	
		return;
}

static struct rbtree *find_leaf_parent(struct rbtree *root)
{
	if(root == NULL)
		return NULL;
	if(root->left == NULL || root->right ==NULL)
		return root;
	return find_leaf_parent(root->left);
}
static void leaf_check(struct rbtree_root *tree)
{
	if(tree->root == NULL)
	{
		tree->leaf_parent = NULL;
		return;
	}

	if(tree->leaf_parent == NULL)
		tree->leaf_parent = find_leaf_parent(tree->root);
	
	if(tree->leaf_parent->left != NULL && tree->leaf_parent->right != NULL)
		tree->leaf_parent = find_leaf_parent(tree->root);
}

static struct rbtree *find_successor(struct rbtree *target)
{
	struct rbtree *tmp = NULL;

	if(target->right != NULL)
	{
		tmp = target->right;
		while(tmp->left != NULL)	tmp = tmp->left;
		return tmp;
	}
	else if(target->parent != NULL)
	{
		tmp = target;
		while(tmp->parent != NULL && tmp->parent->right == tmp)
			tmp = tmp->parent;
		
		return tmp->parent;
	}
	else
		return NULL;
}

static void insert_check_rbtree(struct rbtree_root *tree, struct rbtree *new)
{
	struct rbtree *root = tree->root;
	struct rbtree *parent = new->parent;
	struct rbtree *uncle = parent ? (parent->brother) : NULL;
	struct rbtree *grandfather = parent ? (parent->parent) : NULL;
	int case_id = 0;
	
	#if RB_DEBUG
	print_rbtree(tree->root, 0);
	#endif
	
	if( new == root && new->color == BLACK)				// insert 8
		case_id = 8;
	else if( new == root && new->color == RED)			// insert 1
		case_id = 1;
	else if(parent->color == BLACK)						// insert 7
		case_id = 7;
	else if(parent->color == RED && uncle->color == RED)	// insert 2
		case_id = 2;
	else if(parent->color == RED && uncle->color == BLACK)
	{
		if(parent == grandfather->left && new == parent->left)			// insert 3
			case_id = 3;
		else if(parent == grandfather->left && new == parent->right)	// insert 4
			case_id = 4;
		else if(parent == grandfather->right && new == parent->right)	// insert 5
			case_id = 5;
		else														// insert 6
			case_id = 6;
	}
	#if RB_DEBUG
	printf("insert_check_rbtree  [%d] \n", case_id);
	#endif
	
	switch(case_id)
	{
	case 8:
		goto END;
		break;
	case 1:
		new->color = BLACK;
		break;
	case 7:
		goto END;
		break;
	case 2:
		rb_turn_color(parent);
		rb_turn_color(uncle);
		rb_turn_color(grandfather);
		insert_check_rbtree(tree, grandfather);
		break;
	case 3:
		rb_turn_color(parent);
		rb_turn_color(grandfather);
		right_rotate(tree, grandfather);
		break;
	case 4:
		left_rotate(tree, parent);
		insert_check_rbtree(tree, parent);
		break;
	case 5:
		rb_turn_color(parent);
		rb_turn_color(grandfather);
		left_rotate(tree, grandfather);
		break;
	case 6:
		right_rotate(tree, parent);
		insert_check_rbtree(tree, parent);
		break;
	default:
		printf("insert_check_rbtree [else] \n");
		break;
	}
END:
	#if RB_DEBUG
	print_rbtree(tree->root, 0);
	#endif
	
	return;
}

static void remove_check_rbtree(struct rbtree_root *tree, struct rbtree *target)
{
	return;
}

int exist_rbnode(struct rbtree_root *tree, struct rbtree *node)
{
	return 1;
}
void insert_rbnode(struct rbtree_root *tree, struct rbtree *node)
{
	INIT_RBTREE(node);
	if(tree->root == NULL)
	{
		tree->root = node;
		tree->leaf_parent = node;
	}
	else
	{
		if(tree->leaf_parent->left == NULL)
		{
			tree->leaf_parent->left = node;
			node->brother = tree->leaf_parent->right;
		}
		else
		{
			tree->leaf_parent->right = node;
			node->brother = tree->leaf_parent->left;
		}

		node->parent = tree->leaf_parent;

		if(tree->leaf_parent->right != NULL)
			tree->leaf_parent = node;
	}
	
	insert_check_rbtree(tree, node);
	leaf_check(tree);
}

void remove_rbnode(struct rbtree_root *tree, struct rbtree *node)
{
	struct rbtree *nc = NULL, *successor = NULL;

	if(node->left != NULL && node->right != NULL)
	{
		// 寻找前继节点或后继节点，此处选择寻找后继节点
		successor = find_successor(node);
		exchange_rbtree(tree, node, successor);
	}

	remove_check_rbtree(tree, node);
	
	if(node->left == NULL && node->right == NULL)
	{
		if(tree->root == node)
		{
			tree->root = NULL;
			goto END;
		}

		if(node->brother)
			node->brother->brother = NULL;

		if(node == node->parent->left)
			node->parent->left = NULL;
		else
			node->parent->right = NULL;

		if(tree->leaf_parent == node)
			tree->leaf_parent = node->parent;
	}
	else
	{
		if(node->right != NULL)
			nc = node->right;
		if(node->left != NULL)
			nc = node->left;
		// else: error
		
		if(tree->root == node)
		{
			tree->root = nc;
			nc->brother = NULL;
			nc->parent = NULL;
			goto END;
		}
		
		nc->brother = node->brother;
		nc->parent = node->parent;

		if(node->brother)
			node->brother->brother = nc;

		if(node == node->parent->left)
			node->parent->left = nc;
		else
			node->parent->right = nc;
		
		if(tree->leaf_parent == node)
			tree->leaf_parent = NULL;
	}
	
END:
	leaf_check(tree);
	return;
}

// 中序遍历
void rbtree_inorder_traversal(struct rbtree *root, RB_CALL call, void *data, unsigned int size)
{
	if(root == NULL)
		return;
	
	rbtree_inorder_traversal(root->left, call, data, size);
	if(call)
		call(root, data, size);
	rbtree_inorder_traversal(root->right, call, data, size);
}

// 后序遍历
void rbtree_postorder_traversal(struct rbtree *root, RB_CALL call, void *data, unsigned int size)
{
	if(root == NULL)
		return;
	
	rbtree_postorder_traversal(root->left, call, data, size);
	rbtree_postorder_traversal(root->right, call, data, size);
	if(call)
		call(root, data, size);
}

// 先序遍历
void rbtree_preorder_traversal(struct rbtree *root, RB_CALL call, void *data, unsigned int size)
{
	if(root == NULL)
		return;

	if(call)
		call(root, data, size);
	rbtree_preorder_traversal(root->left, call, data, size);
	rbtree_preorder_traversal(root->right, call, data, size);
}

#if 0
struct test
{
	int a;
	struct rbtree tree;
};

#define newline() printf("\n")

void print_tree(struct rbtree *root, int zero)
{
	struct test *t;
	static char str[10][100];
	static int n = 0;
	int i=0;
	char tmp[10];
	
	if(zero > n)	n = zero;
	if(zero == 0)	memset(str, 0, sizeof(str));

	if(root == NULL)
	{
		strcat(str[zero], "N ");
	}
	else
	{
		t = rbtree_entry(root, struct test, tree);
		sprintf(tmp, "%d ", t->a);
		strcat(str[zero], tmp);
		printf("zero=%d, a=%d \n", zero, t->a);
	}
	
	if(root == NULL)
		return;
	
	print_tree(root->left, zero+1);
	print_tree(root->right, zero+1);

	if(zero == 0)
	{
		printf("--- \n");
		for(i=0; i<=n; i++)
		{
			printf("%s \n", str[i]);
		}
	}
}
struct rbtree *m, *n;
void call_traversal(struct rbtree *root, void *data, unsigned int size)
{
	struct test *t;
	if(root == NULL)
		return;

	t = rbtree_entry(root, struct test, tree);
	printf(" %d ", t->a);
	
	if(t->a == 6)	m = root;
	else if(t->a == 10)	n = root;
}
void main()
{
	int i;
	struct test *t;
	//RBTREE_ROOT(tree);
	struct rbtree_root tree;
	INIT_RBTREE_ROOT(&tree);

	for(i=1; i<=10; i++)
	{
		t = (struct test *)malloc(sizeof(struct test));
		if(t == NULL)
		{
			--i;
			continue;
		}
		t->a = i;
		insert_rbnode(&tree, &(t->tree));
	}
	
	printf("preorder \n");
	rbtree_preorder_traversal(tree.root, call_traversal, NULL, 0);newline();
	/*
	printf("postorder \n");
	rbtree_postorder_traversal(tree.root, call_traversal, NULL, 0);newline();
	printf("inorder \n");
	rbtree_inorder_traversal(tree.root, call_traversal, NULL, 0);newline();
	*/
	print_tree(tree.root, 0);
	
	#if RB_DEBUG
	print_rbtree(tree.root, 0);
	#endif

	exchange_rbtree(&tree, m, n);

	print_tree(tree.root, 0);
	
	#if RB_DEBUG
	print_rbtree(tree.root, 0);
	#endif
}
#endif

