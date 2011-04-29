/*
 * mm.c - structure of free and allocated blocks,
 * organization of the free list, how allocator manipulates
 * the free list.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#include "mm.h"
#include "memlib.h"

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

/* double word (8) alignment */
#define ALIGNMENT 8

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~0x7)

/* gets the size of headers and footers */
#define HEADER_SIZE (sizeof(header_t))
#define FOOTER_SIZE (sizeof(footer_t))
#define SIZE_T_SIZE (ALIGN(HEADER_SIZE + FOOTER_SIZE))

/* get pointers to the top and bottom of the heap */
#define HEAP_LO ((char *)mem_heap_lo())
#define HEAP_HI ((char *)mem_heap_hi())

/* sets minimum size of a block */
#define MIN_SIZE 128
#define MIN_BLOCK_SIZE (ALIGN(MIN_SIZE + SIZE_T_SIZE))

/* get pointers to header, body, and footer of a block */
#define GET_HEADER(p) ((header_t *)((char *)(p) - HEADER_SIZE));
#define GET_BODY(p) ((void *)((char *)p + HEADER_SIZE))
#define GET_FOOTER(p) ((footer_t *)((char *)p + (GET_SIZE(p) - FOOTER_SIZE)))

/* get the size of the body of a block */
#define GET_BODY_SIZE(size) (size - SIZE_T_SIZE)

/* get a pointer to the middle of a block, used for splitting */
#define GET_BLOCK(p,size) ((header_t *)((char *)p + size))

/* get pointers to the previous and next blocks in the heap */
#define GET_PREV_BLOCK(p) ((header_t *)((char *)p - ((footer_t *)((char *)p - FOOTER_SIZE))->size))
#define GET_NEXT_BLOCK(p) ((header_t *)((char *)p + GET_SIZE(p)))

/* get pointers to the previous and next blocks in the free list */
#define GET_PREV(p) (p->prev)
#define GET_NEXT(p) (GET_FOOTER(p)->next)

/* check if a block is in the heap */
#define IS_VALID_BLOCK(p) ((char *)p >= HEAP_LO && (char *)p <= HEAP_HI)

/* check if a block is free */
#define IS_FREE(p) (p->size & 1)

/* mark a block as free or allocated */
#define MARK_FREE(p) (p->size = p->size | 1)
#define MARK_ALLOC(p) (p->size = GET_SIZE(p))

/* get the size of a block */
#define GET_SIZE(p) (p->size & 0xfffffffe)

/* set the number of free lists */
#define FREE_LISTS 8

/* null pointer */
#define NULL_BLOCK (void *)-1

/* block header tag */
typedef struct header_t {
	size_t size;			// size of block, allocated or free
	struct header_t *prev;	// pointer to previous free block in class
} header_t;

/* block footer tag */
typedef struct footer_t {
	size_t size;			// size of block
	struct header_t *next;	// pointer to next free block in class
} footer_t;

/* segregated free lists */
static header_t *free_list[FREE_LISTS];

/* helper functions */
static header_t *split_block(header_t *p, size_t size);
static header_t *coalesce(header_t *p);
static header_t *new_block(size_t size);
static header_t *find_block(size_t size);
static void set_alloc(header_t *p);
static void set_free(header_t *p);
static void remove_from_free_list(header_t *p);
static int get_class(size_t size);

/* checker functions */
static int check_coalesce(void);
static int check_free_list(void);
static int check_heap(void);

/* 
 * mm_init - Initialize the segregated free lists to be empty.
 */
int mm_init(void) {
	int i;
	for (i = 0; i < FREE_LISTS; i++)
		free_list[i] = 0;
	return 0;
}

/* 
 * mm_malloc - Try to find a free block that will hold the payload.
 * If no free block is found, allocate a new block whose size is a
 * multiple of the alignment.
 */
void *mm_malloc(size_t size) {
	if (size <= 0)
		return NULL;
	header_t *p = find_block(size);
	if (p == NULL_BLOCK)
		if ((p = new_block(size)) == NULL_BLOCK)
			return NULL;
	set_alloc(p);
	return GET_BODY(p);
}

/*
 * mm_free - Mark the block as free and attempt to coalesce.
 */
void mm_free(void *ptr) {
	header_t *p = GET_HEADER(ptr);
	set_free(p);
	coalesce(p);
}

/*
 * mm_realloc - Check if the old block will hold the size.
 * If so, return the old block. If not, attempt to coalesce
 * with neighboring blocks and return a new larger block.
 * And, if all else fails, free the old block and allocate
 * a new block that will hold the payload.
 */
void *mm_realloc(void *ptr, size_t size) {
	/* Null pointer, allocate a new block. */
	if (ptr == NULL) {
		return mm_malloc(size);
	}
	/* Size is zero, so just free the block. */
	else if (size <= 0) {
		mm_free(ptr);
		return NULL;
	}
	/* Reallocate the block or return a new block that fits the payload. */
	else {
		header_t *old_block = GET_HEADER(ptr);
		if (size < MIN_SIZE)
			size = MIN_SIZE;
		size_t newsize = ALIGN(size + SIZE_T_SIZE);
		size_t oldsize = GET_SIZE(old_block);
		/* The old block won't hold the new payload, so attempt to coalesce. */
		if (oldsize < newsize) {
			header_t *prev = GET_PREV_BLOCK(old_block);
			header_t *next = GET_NEXT_BLOCK(old_block);
			if (!IS_VALID_BLOCK(prev) || !IS_FREE(prev) || prev == old_block)
				prev = 0;
			if (!IS_VALID_BLOCK(next) || !IS_FREE(next) || next == old_block)
				next = 0;
			if (prev != 0 && next != 0 && GET_SIZE(prev) + GET_SIZE(old_block) + GET_SIZE(next) < newsize) {
				prev = 0;
				next = 0;
			} else if (prev != 0 && GET_SIZE(prev) + GET_SIZE(old_block) < newsize) {
				prev = 0;
			} else if (next != 0 && GET_SIZE(old_block) + GET_SIZE(next) < newsize) {
				next = 0;
			}
			header_t *new_block;
			/* If the block can't be coalesced, copy the memory to a new block and
			 * free the old one. */
			if (prev == 0 && next == 0) {
				new_block = GET_HEADER(mm_malloc(newsize));
				memcpy(GET_BODY(new_block),GET_BODY(old_block),GET_BODY_SIZE(oldsize));
				mm_free(GET_BODY(old_block));
				set_alloc(new_block);
				return GET_BODY(new_block);
			}
			/* Otherwise free the old block and coalesce. Then move the payload if
			 * the start of the block has changed. */
			else {
				set_free(old_block);
				new_block = coalesce(old_block);
				remove_from_free_list(new_block);
				if (new_block != old_block)
					memcpy(GET_BODY(new_block),GET_BODY(old_block),GET_BODY_SIZE(oldsize));
				set_alloc(new_block);
				return GET_BODY(new_block);
			}
		}
		/* The old block will hold the new payload, so simply return it. */
		else {
			return GET_BODY(old_block);
		}
	}
}

/*
 * split_block - If the block can be split into two chunks each at
 * least as big as the minimum block size, split it, free the leftover
 * segment, and return the smaller original block. Otherwise,
 * return the original block.
 */
static header_t *split_block(header_t *p, size_t size) {
	if (GET_SIZE(p) >= size && (GET_SIZE(p) - size) >= MIN_BLOCK_SIZE) {
		MARK_ALLOC(p);
		header_t *new_block = GET_BLOCK(p,size);
		new_block->size = GET_SIZE(p) - size;
		GET_FOOTER(new_block)->size = GET_SIZE(p) - size;
		p->size = size;
		GET_FOOTER(p)->size = size;;
		set_free(new_block);
		coalesce(new_block);
	}
	return p;
}

/*
 * coalesce - Check the previous and next blocks to see if they are
 * free. If either or both are, remove all the relevant blocks from
 * the free list, combine them into a single larger block, and insert
 * the new block back into the free list.
 */
static header_t *coalesce(header_t *p) {
	header_t *prev = GET_PREV_BLOCK(p);
	header_t *next = GET_NEXT_BLOCK(p);
	if (!IS_VALID_BLOCK(prev) || !IS_FREE(prev) || prev == p)
		prev = 0;
	if (!IS_VALID_BLOCK(next) || !IS_FREE(next) || next == p)
		next = 0;
	/* Previous and next blocks are both allocated. */
	if (prev == 0 && next == 0)
		return p;
	header_t *new_block;
	size_t newsize;
	remove_from_free_list(p);
	/* Previous block is free. */
	if (prev && !next) {
		remove_from_free_list(prev);
		new_block = prev;
		newsize = GET_SIZE(prev) + GET_SIZE(p);
	}
	/* Next block is free. */
	else if (!prev && next) {
		remove_from_free_list(next);
		new_block = p;
		newsize = GET_SIZE(p) + GET_SIZE(next);
	}
	/* Previous and next blocks are free. */
	else {
		remove_from_free_list(prev);
		remove_from_free_list(next);
		new_block = prev;
		newsize = GET_SIZE(prev) + GET_SIZE(p) + GET_SIZE(next);
	}
	new_block->size = newsize;
	GET_FOOTER(new_block)->size = newsize;
	set_free(new_block);
	return new_block;
}

/*
 * new_block - Allocate a new block whose size is a multiple
 * of the alignment.
 */
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
	GET_FOOTER(p)->size = size;
	return p;
}

/*
 * find_block - Search the segregated free lists for a free block
 * that will hold the payload. Return a null pointer if no free block
 * is available.
 */
static header_t *find_block(size_t size) {
	if (size <= 0)
		return NULL_BLOCK;
	if (size < MIN_SIZE)
		size = MIN_SIZE;
	size = ALIGN(size + SIZE_T_SIZE);
	int class;
	header_t *p;
	/* Iterate over the free lists starting at the initial size class
	 * until a large enough free block is found. */
	for (class = get_class(size); class < FREE_LISTS; class++) {
		p = free_list[class];
		while (p != 0 && GET_SIZE(p) < size)
			p = GET_NEXT(p);
		/* Remove free block from list and split it */
		if (p != 0) {
			remove_from_free_list(p);
			return split_block(p,size);
		}
	}
	/* No free block found */
	return NULL_BLOCK;
}

/*
 * set_alloc -
 */
static void set_alloc(header_t *p) {
	MARK_ALLOC(p);
	p->prev = 0;
	GET_FOOTER(p)->next = 0;
}

/*
 * set_free -
 */
static void set_free(header_t *p) {
	int class = get_class(GET_SIZE(p));
	MARK_FREE(p);
	p->prev = 0;
	GET_FOOTER(p)->next = free_list[class];
	if (free_list[class] != 0)
		free_list[class]->prev = p;
	free_list[class] = p;
}

/*
 * remove_from_free_list -
 */
static void remove_from_free_list(header_t *p) {
	int class = get_class(GET_SIZE(p));
	if (GET_PREV(p) != 0)
		GET_FOOTER(GET_PREV(p))->next = GET_NEXT(p);
	if (GET_NEXT(p) != 0)
		GET_NEXT(p)->prev = GET_PREV(p);
	if (free_list[class] == p)
		free_list[class] = GET_NEXT(p);
}

/*
 * get_class -
 */
static int get_class(size_t size) {
	if (size < 256)
		return 0;
	else if (size < 512)
		return 1;
	else if (size < 1024)
		return 2;
	else if (size < 2048)
		return 3;
	else if (size < 4096)
		return 4;
	else if (size < 8192)
		return 5;
	else if (size < 16384)
		return 6;
	else
		return 7;
}

/*
 * check_coalesce - Verify that all free blocks have been coalesced.
 */
static int check_coalesce() {
	int valid = 1;
	header_t *prev = NULL_BLOCK;
	header_t *next;
	header_t *p = mem_heap_lo();
	char *top = (char *)mem_heap_hi();
	while ((char *)p < top) {
		next = GET_NEXT_BLOCK(p);
		if (IS_FREE(p) && IS_FREE(next))
			valid = 0;
		prev = p;
		p = next;
	}
	return valid;
}

/*
 * check_free_list - Verify that every block in the free list is free.
 */
static int check_free_list(void) {
	int class;
	header_t *p;
	int valid = 1;
	for (class = 0; class < FREE_LISTS; class++) {
		p = free_list[class];
		while (p != 0) {
			if (!IS_FREE(p)) {
				printf("Error: allocated block on free list %d",class);
				valid = 0;
			}
			if (!IS_FREE(GET_PREV(p))) {
				printf("Error: pointer to allocated block in free list %d",class);
			}
			p = GET_NEXT(p);
		}
	}
	return valid;
}

/*
 * check_heap - Verify that every free block in the heap is in a free list.
 */
static int check_heap(void) {
	header_t *p = (header_t *)HEAP_LO;
	header_t *list;
	int valid = 1;
	while ((char *)p < HEAP_HI) {
		if (IS_FREE(p)) {
			list = free_list[get_class(p->size)];
			while (list != 0 && list != p)
				list = GET_NEXT(list);
			if (list != p) {
				printf("Error: free block not in a free list");
				valid = 0;
			}
		}
		p = GET_NEXT_BLOCK(p);
	}
	return valid;
}

/*
 * mm_check -
 * It will check any invariants or consistency conditions you consider prudent.
 * It returns a nonzero value if and only if your heap is consistent.
 * You are encouraged to print out error messages when mm check fails.
 * Is every block in the free list marked as free? X
 * Are there any contiguous free blocks that somehow escaped coalescing? X
 * Is every free block actually in the free list? X
 * Do the pointers in the free list point to valid free blocks? X
 * Do any allocated blocks overlap?
 * Do the pointers in a heap block point to valid heap addresses?
 */
int mm_check(void) {
	if (!check_free_list() || !check_heap() || !check_coalesce())
		return 0;
	else
		return 1;
}