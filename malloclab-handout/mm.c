/*
 * mm.c - Implements a memory allocation package that includes the
 * malloc, free, and realloc functions.
 * 
 * This approach uses explicit segregated free lists to store blocks.
 * Each segregated list is a doubly linked-list corresponding to a
 * specific size class. Each block is made of up a header and a footer,
 * which contain the size of the block and pointers to the previous
 * and next blocks in the corresponding free list.
 * 
 * Allocated blocks are placed using a first fit policy. In order to
 * prevent fragmentation, splitting is used during the allocation of
 * blocks. Additionally, immediate coalescing is attempted each time
 * a block is freed.
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
static int check_free_list(void);
static int check_heap(void);
static int mm_check(void);

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
			/* Examine previous and next blocks for possible coalescing. */
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
 * the new block back into the appropriate free list.
 */
static header_t *coalesce(header_t *p) {
	/* Examine previous and next blocks for possible coalescing. */
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
 * set_alloc - Mark the block as allocated and set it so
 * that is no longer points to any other block.
 */
static void set_alloc(header_t *p) {
	MARK_ALLOC(p);
	p->prev = 0;
	GET_FOOTER(p)->next = 0;
}

/*
 * set_free - Mark the block as free and insert it into one of
 * the free lists based on its size class.
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
 * remove_from_free_list - Remove the block from the free list by
 * adjusting its incoming pointers.
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
 * get_class - Return an integer corresponding to the size class
 * of a block. This will help to determine which part of the
 * segregated free list to use.
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
 * check_free_list - Verify that every block in the free list is free.
 * Also check that there are no pointers to allocated blocks. Returns
 * one if and only if the free lists are consistent.
 */
static int check_free_list(void) {
	int class;
	header_t *p;
	int valid = 1;
	for (class = 0; class < FREE_LISTS; class++) {
		p = free_list[class];
		while (p != 0) {
			/* Make sure every block in free list is actually free. */
			if (!IS_FREE(p)) {
				printf("Error: allocated block on free list %d",class);
				valid = 0;
			}
			/* Make sure no block header points to an allocated block. */
			if (IS_VALID_BLOCK(GET_PREV(p)) && GET_PREV(p) != p && !IS_FREE(GET_PREV(p))) {
				printf("Error: pointer to allocated block in free list %d",class);
				valid = 0;
			}
			p = GET_NEXT(p);
		}
	}
	return valid;
}

/*
 * check_heap - Verify that every free block in the heap is in a free list.
 * Verify that no contiguous free blocks have escaped coalescing. Verify that
 * all block headers and footers have consistent sizes. Returns one if
 * and only if the heap is consistent.
 * WARNING: This function takes several minutes to run on the binary-bal traces.
 */
static int check_heap(void) {
	header_t *p = (header_t *)HEAP_LO;
	header_t *list, *next;
	int valid = 1;
	while ((char *)p < HEAP_HI) {
		next = GET_NEXT_BLOCK(p);
		/* Check header and footer size consistency. */
		if (GET_SIZE(p) != GET_FOOTER(p)->size) {
			printf("Error: inconsistent sizes in block header and footer.\n");
			valid = 0;
		}
		if (IS_FREE(p)) {
			/* Check for blocks that missed coalescing. */
			if (IS_VALID_BLOCK(next) && next != p && IS_FREE(next)) {
				printf("Error: free blocks not coalesced.\n");
				valid = 0;
			}
			list = free_list[get_class(p->size)];
			/* Make sure free block is in the correct free list. */
			while (list != p) {
				if (list == 0) {
					printf("Error: free block not in a free list.\n");
					valid = 0;
					break;
				}
				list = GET_NEXT(list);
			}
		}
		p = next;
	}
	return valid;
}

/*
 * mm_check - Checks the free list and heap for consistency. Returns one
 * if and only if the free lists and heap are consistent. See
 * check_free_list() and check_heap() for more details.
 */
int mm_check(void) {
	if (!check_free_list() || !check_heap())
		return 0;
	else
		return 1;
}
