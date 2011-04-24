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

#define GET_FOOTER(p) ((char *)p + (p->size - FOOTER_SIZE))
#define GET_PREV_BLOCK(p) (((footer_t *)((char *)p - FOOTER_SIZE))->header)
#define GET_NEXT_BLOCK(p) ((char *)p + p->size)

#define ALLOC '0'
#define FREE '1'
#define END '2'

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
	else if (size < MIN_SIZE)
		size = MIN_SIZE;
	size_t newsize = ALIGN(size + SIZE_T_SIZE);
	header_t *p;
	if (!free_list) {
		p = mem_sbrk(newsize);
		p->size = newsize;
	} else {
		p = free_list;
		while (p != 0 && p->size < newsize) {
			p = p->next;
		}
		if (p == 0) {
			p = mem_sbrk(newsize);
			if (p != (void *)-1)
				p->size = newsize;
		} else {
			if (p->prev != 0)
				p->prev->next = p->next;
			if (p->next != 0)
				p->next->prev = p->prev;
			if (free_list == p)
				free_list = p->next;
			if (p->size > newsize && (p->size - newsize) >= ALIGN(MIN_SIZE + SIZE_T_SIZE))
				p = split_block(p,newsize);
		}
	}
	if (p == (void *)-1) {
		return NULL;
	} else {
		p->status = ALLOC;
		p->next = 0;
		p->prev = 0;
		((footer_t *)GET_FOOTER(p))->header = p;
		return (void *)((char *)p + HEADER_SIZE);
	}
}

/*
 * mm_free - Freeing a block does nothing.
 */
void mm_free(void *ptr) {
	header_t *p = (header_t *)((char *)(ptr) - HEADER_SIZE);
	header_t *free = free_list;
	p->status = FREE;
	p->prev = 0;
	p->next = free;
	if (free != 0)
		free->prev = p;
	free_list = p;
	p = coalesce(p);
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
		header_t *old_block = (header_t *)((char *)ptr - HEADER_SIZE);
		if (size < MIN_SIZE)
			size = MIN_SIZE;
		size_t newsize = ALIGN(size + SIZE_T_SIZE);
		size_t oldsize = old_block->size;
		if (old_block->size < newsize) {
			header_t *prev = (header_t *)GET_PREV_BLOCK(old_block);
			header_t *next = (header_t *)GET_NEXT_BLOCK(old_block);
			char *lo = mem_heap_lo();
			char *hi = mem_heap_hi();

			if ((char *)prev < lo || (char *)prev > hi)
				prev = 0;
			else
				prev = prev->status == FREE ? prev : 0;
			if ((char *)next < lo || (char *)next > hi)
				next = 0;
			else
				next = next->status == FREE ? next : 0;

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
				new_block = (header_t *)((char *)mm_malloc(newsize) - HEADER_SIZE);
				memcpy((char *)new_block + HEADER_SIZE, (char *)old_block + HEADER_SIZE, old_block->size);
				mm_free((char *)old_block + HEADER_SIZE);
				return (char *)new_block + HEADER_SIZE;
			} else {
				header_t *free = free_list;
				old_block->status = FREE;
				old_block->prev = 0;
				old_block->next = free;
				if (free != 0)
					free->prev = old_block;
				free_list = old_block;
				new_block = coalesce(old_block);
				if (new_block->next != 0)
					new_block->next->prev = 0;
				free_list = new_block->next;
				if (new_block != old_block)
					memcpy((char *)new_block + HEADER_SIZE, (char *)old_block + HEADER_SIZE, oldsize);
//				if (new_block->size > newsize && (new_block->size - newsize) >= ALIGN(MIN_SIZE + SIZE_T_SIZE))
//					new_block = split_block(new_block,newsize);
				new_block->status = ALLOC;
				return (char *)new_block + HEADER_SIZE;
			}
		} /*else if (old_block->size > newsize) {
			old_block = split_block(old_block,newsize);
			old_block->status = ALLOC;
		}*/
		return (char *)old_block + HEADER_SIZE;
	}
}

static header_t *split_block(header_t *p, size_t size) {
	header_t *new_block = (header_t *)((char *)p + size);
	new_block->size = p->size - size;
	new_block->status = FREE;
	new_block->next = p->next;
	new_block->prev = p->prev;
	if (new_block->next != 0)
		new_block->next->prev = new_block;
	if (new_block->prev != 0)
		new_block->prev->next = new_block;
	else
		free_list = new_block;
	p->size = size;
	((footer_t *)GET_FOOTER(p))->header = p;
	((footer_t *)GET_FOOTER(new_block))->header = new_block;
	return p;
}

static header_t *coalesce(header_t *p) {
	header_t *prev = (header_t *)GET_PREV_BLOCK(p);
	header_t *next = (header_t *)GET_NEXT_BLOCK(p);
	char *lo = mem_heap_lo();
	char *hi = mem_heap_hi();

	if ((char *)prev < lo || (char *)prev > hi)
		prev = 0;
	else
		prev = prev->status == FREE ? prev : 0;
	if ((char *)next < lo || (char *)next > hi)
		next = 0;
	else
		next = next->status == FREE ? next : 0;

	if (prev == 0 && next == 0) {
		return p;
	}

	header_t *new_block;
	if (prev && !next) {
		new_block = prev;
		if (prev->next != p) {
			if (prev->prev != 0)
				prev->prev->next = prev->next;
			if (prev->next != 0)
				prev->next->prev = prev->prev;
		}
		new_block->next = p->next;
		if (new_block->next != 0)
			new_block->next->prev = new_block;
		new_block->prev = 0;
		new_block->size = prev->size + p->size;
		free_list = new_block;
	} else if (!prev && next) {
		new_block = p;
		if (p->next == next) {
			new_block->next = next->next;
			if (new_block->next != 0)
				new_block->next->prev = new_block;
		} else {
			if (next->prev != 0)
				next->prev->next = next->next;
			if (next->next != 0)
				next->next->prev = next->prev;
		}
		new_block->size = p->size + next->size;
	} else {
		new_block = prev;
		if (prev->next != p) {
			if (prev->prev != 0)
				prev->prev->next = prev->next;
			if (prev->next != 0)
				prev->next->prev = prev->prev;
		}
		new_block->prev = 0;
		if (p->next == next) {
			new_block->next = next->next;
		} else {
			new_block->next = p->next;
			if (next->prev != 0)
				next->prev->next = next->next;
			if (next->next != 0)
				next->next->prev = next->prev;
		}
		if (new_block->next != 0)
			new_block->next->prev = new_block;
		new_block->size = prev->size + p->size + next->size;
		free_list = new_block;
	}
	((footer_t *)GET_FOOTER(new_block))->header = new_block;
	return new_block;
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
