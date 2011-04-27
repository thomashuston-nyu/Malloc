/*
 * mm-naive.c - The fastest, least memory-efficient malloc package.
 * 
 * In this naive approach, a block is allocated by simply incrementing
 * the brk pointer.  A block is pure payload. There are no headers or
 * footers.  Blocks are never coalesced or reused. Realloc is
 * implemented directly using mm_malloc and mm_free.
 *
 * NOTE TO STUDENTS: Your code should begin with a header comment that
 * describes the structure of your free and allocated blocks, the
 * organization of the free list, and how your allocator manipulates
 * the free list. each function should be preceeded by a header comment
 * that describes what the function does.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#include "mm.h"
#include "memlib.h"

/*********************************************************
 * NOTE TO STUDENTS: Before you do anything else, please
 * provide your team information in the following struct.
 ********************************************************/
team_t team = {
		/* Team name */
		"Mike & Thomas",
		/* First member's full name */
		"Thomas Huston",
		/* First member's NYU NetID*/
		"tph227@nyu.edu",
		/* Second member's full name (leave blank if none) */
		"Mike Morreale",
		/* Second member's email address (leave blank if none) */
		"mjm737@nyu.edu"
};

/* single word (4) or double word (8) alignment */
#define ALIGNMENT 8

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~0x7)

#define HEADER_SIZE (ALIGN(sizeof(header_t)))
#define FOOTER_SIZE (ALIGN(sizeof(footer_t)))
#define SIZE_T_SIZE (ALIGN(HEADER_SIZE + FOOTER_SIZE))

#define MIN_SIZE 128
#define MIN_BLOCK_SIZE (ALIGN(MIN_SIZE + SIZE_T_SIZE))

#define GET_HEADER(p) ((header_t *)((char *)(p) - HEADER_SIZE));
#define GET_BODY(p) ((void *)((char *)p + HEADER_SIZE))
#define GET_FOOTER(p) ((footer_t *)((char *)p + (p->size - FOOTER_SIZE)))
#define SET_FOOTER(p) (((footer_t *)GET_FOOTER(p))->header = p)

#define GET_BODY_SIZE(size) (size - SIZE_T_SIZE)

#define GET_BLOCK(p,size) ((header_t *)((char *)p + size))
#define GET_PREV_BLOCK(p) ((header_t *)(((footer_t *)((char *)p - FOOTER_SIZE))->header))
#define GET_NEXT_BLOCK(p) ((header_t *)((char *)p + p->size))

#define IS_VALID_BLOCK(p) ((char *)p >= (char *)mem_heap_lo() && (char *)p <= (char *)mem_heap_hi())

#define ALLOC '0'
#define FREE '1'

#define NULL_BLOCK (void *)-1

typedef struct header_t {
	char status;
	size_t size;
	struct header_t *parent;
	struct header_t *left;
	struct header_t *right;
	struct header_t *prev;
	struct header_t *next;
} header_t;

typedef struct footer_t {
	struct header_t *header;
} footer_t;

static header_t *free_list;

static header_t *split_block(header_t *p, size_t size);
static header_t *coalesce(header_t *p);
static header_t *new_block(size_t size);
static header_t *find_block(size_t size);
static void set_alloc(header_t *p);
static void set_free(header_t *p);
static void remove_from_free_list(header_t *p);


/* 
 * mm_init - initialize the malloc package.
 */
int mm_init(void) {
	free_list = 0;
	return 0;
}

/* 
 * mm_malloc - Allocate a block by incrementing the brk pointer.
 *     Always allocate a block whose size is a multiple of the alignment.
 */
void *mm_malloc(size_t size) {
	if (size <= 0)
		return NULL;
	header_t *p = find_block(size);
	if (p == NULL_BLOCK)
		if ((p = new_block(size)) == NULL_BLOCK)
			return NULL;
	set_alloc(p);
//	printf("malloc %x\n",p);
//	mm_check();
	return GET_BODY(p);
}

/*
 * mm_free - Freeing a block does nothing.
 */
void mm_free(void *ptr) {
	header_t *p = GET_HEADER(ptr);
	set_free(p);
	coalesce(p);
}

/*
 * mm_realloc - Implemented simply in terms of mm_malloc and mm_free
 */
void *mm_realloc(void *ptr, size_t size) {
//	return mm_malloc(size);
	if (ptr == NULL)
		return mm_malloc(size);
	else if (size <= 0) {
		mm_free(ptr);
		return NULL;
	} else {
		header_t *old_block = GET_HEADER(ptr);
		if (size < MIN_SIZE)
			size = MIN_SIZE;
		size_t newsize = ALIGN(size + SIZE_T_SIZE);
		size_t oldsize = old_block->size;
		if (old_block->size < newsize) {
			header_t *prev = GET_PREV_BLOCK(old_block);
			header_t *next = GET_NEXT_BLOCK(old_block);

			if (!IS_VALID_BLOCK(prev) || prev->status == ALLOC)
				prev = 0;
			if (!IS_VALID_BLOCK(next) || next->status == ALLOC)
				next = 0;

			if (prev != 0 && next != 0 && prev->size + old_block->size + next->size < newsize) {
				prev = 0;
				next = 0;
			} else if (prev != 0 && prev->size + old_block->size < newsize) {
				prev = 0;
			} else if (next != 0 && old_block->size < newsize) {
				next = 0;
			}

			header_t *new_block;

			if (prev == 0 && next == 0) {
				new_block = GET_HEADER(mm_malloc(newsize));
				memcpy(GET_BODY(new_block),GET_BODY(old_block),GET_BODY_SIZE(oldsize));
				mm_free(GET_BODY(old_block));
				set_alloc(new_block);
				return GET_BODY(new_block);
			} else {
				set_free(old_block);
				new_block = coalesce(old_block);
				remove_from_free_list(new_block);
				if (new_block != old_block)
					memcpy(GET_BODY(new_block),GET_BODY(old_block),GET_BODY_SIZE(oldsize));
//				new_block = split_block(new_block,newsize);
				set_alloc(new_block);
				return GET_BODY(new_block);
			}
		} /*else if (old_block->size > newsize) {
			old_block = split_block(old_block,newsize);
			set_alloc(old_block);
		}*/
			return GET_BODY(old_block);
	}
}

static header_t *split_block(header_t *p, size_t size) {
	if (p->size >= size && (p->size - size) >= MIN_BLOCK_SIZE) {
		header_t *new_block = GET_BLOCK(p,size);
		new_block->size = p->size - size;
		p->size = size;
		SET_FOOTER(p);
		set_alloc(new_block);
		set_free(new_block);
		SET_FOOTER(new_block);
	}
	return p;
}

static header_t *coalesce(header_t *p) {
	header_t *prev = GET_PREV_BLOCK(p);
	header_t *next = GET_NEXT_BLOCK(p);
	if (!IS_VALID_BLOCK(prev) || prev->status == ALLOC)
		prev = 0;
	if (!IS_VALID_BLOCK(next) || next->status == ALLOC)
		next = 0;

	if (prev == 0 && next == 0) {
		return p;
	}

//	mm_check();
//	printf("\nthe blocks:\n");
//	printf("block\t\tprev\t\tnext\t\tparent\t\tleft\t\tright\t\tsize\tstatus\n");
//	if (prev != 0)
//		printf("prev %11x\t%11x\t%11x\t%11x\t%11x\t%11x\t%d\t%c\n",prev,prev->prev,prev->next,prev->parent,prev->left,prev->right,prev->size,prev->status);
//	printf("this %11x\t%11x\t%11x\t%11x\t%11x\t%11x\t%d\t%c\n",p,p->prev,p->next,p->parent,p->left,p->right,p->size,p->status);
//	if (next != 0)
//		printf("next %11x\t%11x\t%11x\t%11x\t%11x\t%11x\t%d\t%c\n",next,next->prev,next->next,next->parent,next->left,next->right,next->size,next->status);

//	return p;

	header_t *new_block;
	remove_from_free_list(p);
	if (prev && !next) {
		remove_from_free_list(prev);
		new_block = prev;
		new_block->size = prev->size + p->size;
	} else if (!prev && next) {
		remove_from_free_list(next);
		new_block = p;
		new_block->size = p->size + next->size;
	} else {
		remove_from_free_list(prev);
		remove_from_free_list(next);
		new_block = prev;
		new_block->size = prev->size + p->size + next->size;
	}
	SET_FOOTER(new_block);
	set_free(new_block);
	return new_block;
}

static header_t *new_block(size_t size) {
	if (size <= 0)
		return NULL_BLOCK;
	if (size < MIN_SIZE)
		size = MIN_SIZE;
	size = ALIGN(size + SIZE_T_SIZE);
	header_t *p = mem_sbrk(size);
	if (p == NULL_BLOCK)
		return NULL_BLOCK;
	p->size = size;
	SET_FOOTER(p);
	return p;
}

static header_t *find_block(size_t size) {
	if (size <= 0 || free_list == 0)
		return NULL_BLOCK;
	if (size < MIN_SIZE)
		size = MIN_SIZE;
	size = ALIGN(size + SIZE_T_SIZE);
	header_t *p = free_list;
	while (p != 0) {
		if (p->size < size && p->right != 0)
			p = p->right;
		else if (p->size > size && p->left != 0)
			p = p->left;
		else
			break;
	}
	if (p == 0 || p->size < size)
		return NULL_BLOCK;
	remove_from_free_list(p);
//	return p;
	return split_block(p,size);
}

static void set_alloc(header_t *p) {
	p->status = ALLOC;
	p->parent = 0;
	p->left = 0;
	p->right = 0;
	p->next = 0;
	p->prev = 0;
}

static void set_free(header_t *p) {
	int x = 0;
	set_alloc(p);
	p->status = FREE;
	if (free_list != 0) {
		header_t *node = free_list;
		while (1) {
			if (node->size < p->size) {
				if (node->right != 0) {
					node = node->right;
				} else {
					x = 1;
					node->right = p;
					p->parent = node;
					break;
				}
			} else if (node->size > p->size) {
				if (node->left != 0) {
					node = node->left;
				} else {
					x = 2;
					node->left = p;
					p->parent = node;
					break;
				}
			} else {
				x = 3;
				p->next = node;
				node->prev = p;
				p->left = node->left;
				if (p->left != 0) {
					p->left->parent = p;
					node->left = 0;
				}
				p->right = node->right;
				if (p->right != 0) {
					p->right->parent = p;
					node->right = 0;
				}
				p->parent = node->parent;
				if (p->parent != 0) {
					if (p->parent->left == node)
						p->parent->left = p;
					else
						p->parent->right = p;
					node->parent = 0;
				} else {
					free_list = p;
				}
				break;
			}
		}
	} else {
		free_list = p;
	}
}

static void remove_from_free_list(header_t *p) {
//	int x = 0;
//	header_t *a, *b, *c, *d, *e;
//	a = p->parent;
//	b = p->left;
//	c = p->right;
//	d = p->prev;
//	e = p->next;
//	printf("ptr\t\tblock\t\tprev\t\tnext\t\tparent\t\tleft\t\tright\n");
//	printf("pre:\n");
//	removed(p);
//	printf("%11x\t%11x\t%11x\t%11x\t%11x\t%11x\t%11x\n",p,p,d,e,a,b,c);
	if (p->prev != 0) {
//		x = 1;
		p->prev->next = p->next;
		if (p->next != 0)
			p->next->prev = p->prev;
	} else {
		if (p->next != 0) {
//			x = 2;
//			mm_check();
			p->next->prev = 0;
			p->next->parent = p->parent;
			if (p->parent != 0) {
				if (p->parent->left == p)
					p->parent->left = p->next;
				else
					p->parent->right = p->next;
			} else {
				free_list = p->next;
			}
			if (p->left != 0) {
				p->next->left = p->left;
				p->next->left->parent = p->next;
			}
			if (p->right != 0) {
				p->next->right = p->right;
				p->next->right->parent = p->next;
			}
//			mm_check();
//			printf("%11x\t%11x\t%11x\t%11x\t%11x\t%11x\t%11x\n",p,p,d,e,a,b,c);
		} else {
			if (p->left != 0 && p->right != 0) {
//				x = 3;
				header_t *replace = p->right;
				while (replace->left != 0) {
					replace = replace->left;
				}
				if (replace->right != 0 && replace->parent != p) {
					replace->parent->left = replace->right;
					replace->right->parent = replace->parent;
				} else if (replace->parent != p) {
					replace->parent->left = 0;
				}
				if (p->parent != 0) {
					if (p->parent->left == p)
						p->parent->left = replace;
					else
						p->parent->right = replace;
				} else {
					free_list = replace;
				}
				replace->left = p->left;
				replace->left->parent = replace;
				if (replace->parent != p) {
					replace->right = p->right;
					replace->right->parent = replace;
				}
				replace->parent = p->parent;
			} else if (p->left != 0) {
//				x = 4;
				if (p->parent != 0) {
					if (p->parent->left == p)
						p->parent->left = p->left;
					else
						p->parent->right = p->left;
				} else {
					free_list = p->left;
				}
				p->left->parent = p->parent;
			} else if (p->right != 0) {
//				x = 5;
				if (p->parent != 0) {
					if (p->parent->left == p)
						p->parent->left = p->right;
					else
						p->parent->right = p->right;
				} else {
					free_list = p->right;
				}
				p->right->parent = p->parent;
			} else {
//				x = 6;
//				a = p->parent;
//				b = p->left;
//				c = p->right;
//				d = p->prev;
//				e = p->next;
				if (p->parent != 0) {
					if (p->parent->left == p)
						p->parent->left = 0;
					else
						p->parent->right = 0;
				} else {
					free_list = 0;
				}
			}
		}
	}
//	printf("%d\n",x);
//	printf("post:\n");
//	if (!removed(p)) {
//		printf("%11x\t%11x\t%11x\t%11x\t%11x\t%11x\t%11x\n",p,p,d,e,a,b,c);
//		exit(1);
//	}
//	printf("\n\n");
	set_alloc(p);
//	if (x == 1|| x == 6)
//		printf("%d ",x);
//	if (x == 6 && !removed(p)) {
//		printf("! ");
//		printf("p:%x par:%x l:%x r:%x pr:%x nx:%x ",p,a,b,c,d,e);
//		printf("%x\n",p);
//	}
}

void dfs(header_t *p) {
	if (p == 0)
		return;
	if (p->left != 0)
		dfs(p->left);
	header_t *list = p;
	int i = 0;
	while (list != 0) {
		printf("%c%11x\t%11x\t%11x\t%11x\t%11x\t%11x\t%d\t%c\n",(i == 0 ? '*' : ' '),list,list->prev,list->next,list->parent,list->left,list->right,list->size,list->status);
		list = list->next;
		i++;
	}
	if (p->right != 0)
		dfs(p->right);
}

int in_heap(header_t *ptr) {
	char *top = (char *)mem_heap_hi();
	header_t *p = mem_heap_lo();
	while ((char *)p < top) {
		if (p == ptr)
			return 1;
		p = GET_NEXT_BLOCK(p);
	}
	return 0;
}

int removed(header_t *ptr) {
	char *top = (char *)mem_heap_hi();
	header_t *p = mem_heap_lo();
	int removed = 1;
	while ((char *)p < top) {
		if (p->prev == ptr || p->next == ptr || p->parent == ptr || p->left == ptr || p->right == ptr) {
//			printf("\n%11x\t%11x\t%11x\t%11x\t%11x\t%11x\t",p,p->prev,p->next,p->parent,p->left,p->right);
			printf("%11x\t%11x\t%11x\t%11x\t%11x\t%11x\t%11x \n",ptr,p,p->prev,p->next,p->parent,p->left,p->right);
			removed = 0;
		}
		p = GET_NEXT_BLOCK(p);
	}
	return removed;
}

/*
 * mm_check 
 * It will check any invariants or consistency conditions you consider prudent.
 * It returns a nonzero value if and only if your heap is consistent.
 * You are encouraged to print out error messages when mm check fails.
 * Is every block in the free list marked as free?
 * Are there any contiguous free blocks that somehow escaped coalescing?
 * Is every free block actually in the free list?
 * Do the pointers in the free list point to valid free blocks?
 * Do any allocated blocks overlap?
 * Do the pointers in a heap block point to valid heap addresses?
 */
int mm_check(void) {
	char *top = (char *)mem_heap_hi();
	header_t *p = mem_heap_lo();
	printf("\nthe heap:\n");
	printf("block\t\tprev\t\tnext\t\tparent\t\tleft\t\tright\t\tsize\tstatus\n");
	while ((char *)p < top) {
		printf(" %11x\t%11x\t%11x\t%11x\t%11x\t%11x\t%d\t%c\n",p,p->prev,p->next,p->parent,p->left,p->right,p->size,p->status);
		p = GET_NEXT_BLOCK(p);
	}
//	printf("\n");
//	printf("\nthe free tree:\n");
//	printf("block\t\tprev\t\tnext\t\tparent\t\tleft\t\tright\t\tsize\tstatus\n");
//	dfs(free_list);
//	printf("\n");
	/*	printf("the free list:\n");
	printf("block\t\tprev\t\tnext\t\tsize\tstatus\n");
	p = free_list;
	while (p != 0) {
		printf("%11x\t%11x\t%11x\t%d\t%c\n",p,p->prev,p->next,p->size,p->status);
		p = p->next;
	}
	printf("\n");*/
	return 0;
}
