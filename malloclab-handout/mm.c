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

#define HEADER_SIZE (sizeof(header_t))
#define FOOTER_SIZE (sizeof(footer_t))
#define SIZE_T_SIZE (ALIGN(HEADER_SIZE + FOOTER_SIZE))

#define MIN_SIZE 8
#define MIN_BLOCK_SIZE (ALIGN(MIN_SIZE + SIZE_T_SIZE))

#define GET_HEADER(p) ((header_t *)((char *)(p) - HEADER_SIZE));
#define GET_BODY(p) ((void *)((char *)p + HEADER_SIZE))
#define GET_FOOTER(p) ((footer_t *)((char *)p + (p->size - FOOTER_SIZE)))

#define GET_BODY_SIZE(size) (size - SIZE_T_SIZE)

#define GET_BLOCK(p,size) ((header_t *)((char *)p + size))
#define GET_PREV_BLOCK(p) ((header_t *)(((footer_t *)((char *)p - FOOTER_SIZE))->header))
#define GET_NEXT_BLOCK(p) ((header_t *)((char *)p + p->size))

#define IS_VALID_BLOCK(p) ((char *)p >= (char *)mem_heap_lo() && (char *)p <= (char *)mem_heap_hi())

#define SET_FOOTER(p) (((footer_t *)GET_FOOTER(p))->header = p)

#define ALLOC '0'
#define FREE '1'

#define NULL_BLOCK (void *)-1

typedef struct header_t {
	char status;
	size_t size;
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
		set_free(new_block);
		SET_FOOTER(new_block);
		p->size = size;
		SET_FOOTER(p);
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
	set_free(new_block);
	SET_FOOTER(new_block);
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
	if (size <= 0 || !free_list)
		return NULL_BLOCK;
	if (size < MIN_SIZE)
		size = MIN_SIZE;
	size = ALIGN(size + SIZE_T_SIZE);
	header_t *p = free_list;
	while (p != 0 && p->size < size) {
		p = p->next;
	}
	if (p == 0)
		return NULL_BLOCK;
	remove_from_free_list(p);
	return split_block(p,size);
}

static void set_alloc(header_t *p) {
	p->status = ALLOC;
	p->next = 0;
	p->prev = 0;
}

static void set_free(header_t *p) {
	p->status = FREE;
	p->prev = 0;
	p->next = free_list;
	if (free_list != 0)
		free_list->prev = p;
	free_list = p;
}

static void remove_from_free_list(header_t *p) {
	if (p->prev != 0)
		p->prev->next = p->next;
	if (p->next != 0)
		p->next->prev = p->prev;
	if (free_list == p)
		free_list = p->next;
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
/*	char *top = (char *)mem_heap_hi();
	header_t *p = mem_heap_lo();
	printf("\nthe heap:\n");
	printf("block\t\tprev\t\tnext\t\tfooter\t\tsize\tstatus\n");
	while ((char *)p < top) {
		printf("%11x\t%11x\t%11x\t%11x\t%d\t%c\n",p,p->prev,p->next,((footer_t *)GET_FOOTER(p))->header,p->size,p->status);
		p = GET_NEXT_BLOCK(p);
	}
	printf("\n");
	printf("the free list:\n");
	printf("block\t\tprev\t\tnext\t\tsize\tstatus\n");
	p = free_list;
	while (p != 0) {
		printf("%11x\t%11x\t%11x\t%d\t%c\n",p,p->prev,p->next,p->size,p->status);
		p = p->next;
	}
	printf("\n");*/
	return 0;
}
