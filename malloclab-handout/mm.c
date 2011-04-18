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

#define SIZE_T_SIZE (ALIGN(sizeof(header_t)))

typedef short free_t;

typedef struct header_t {
	free_t free;
	size_t size;
	struct header_t *next;
} header_t;

static header_t *free_list;

static header_t *split_block(header_t *p,size_t size);


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
	size_t heapsize = mem_heapsize();
	size_t newsize = ALIGN(size + SIZE_T_SIZE);
	header_t *p;
	if (!free_list) {
		p = mem_sbrk(newsize);
		p->size = newsize;
	} else {
		header_t *x = 0;
		p = free_list;
		while (p != 0 && p->size < newsize) {
			x = p;
			p = p->next;
		}
		if (p != 0 && x != 0)
			x->next = p->next;
		else if (p != 0 && x == 0)
			free_list = p->next;
		if (p == 0) {
			p = mem_sbrk(newsize);
			p->size = newsize;
		} else {
			if (p->size > newsize)
				p = split_block(p,newsize);
		}
	}
	if (p == (void *)-1)
		return NULL;
	else {
		p->free = 0;
		p->next = 0;
		return (void *)((char *)p + SIZE_T_SIZE);
	}
}

/*
 * mm_free - Freeing a block does nothing.
 */
void mm_free(void *ptr) {
//	mm_check();
	ptr = (char *)(ptr) - SIZE_T_SIZE;
	((header_t *)(ptr))->free = 1;
	((header_t *)(ptr))->next = free_list;
	free_list = ptr;
}

/*
 * mm_realloc - Implemented simply in terms of mm_malloc and mm_free
 */
void *mm_realloc(void *ptr, size_t size) {
	/*void *oldptr = ptr;
	void *newptr;
	size_t copySize;

	newptr = mm_malloc(size);
	if (newptr == NULL)
		return NULL;
	copySize = *(size_t *)((char *)oldptr - SIZE_T_SIZE);
	if (size < copySize)
		copySize = size;
	memcpy(newptr, oldptr, copySize);
	mm_free(oldptr);
	return newptr;*/
	return;
}

static header_t *split_block(header_t *p, size_t size) {
	if (p->size > size) {
		header_t *new_block = (char *)p + size;
		new_block->size = p->size - size;
		new_block->free = 1;
		new_block->next = free_list;
		free_list = new_block;
		p->size = size;
	}
	return p;
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
	printf("the heap:\n");
	printf("top\t\tblock\t\tsize\tfree\n");
	while ((char *)p < top) {
		printf("%d\t%d\t%d\t%d\n",top,p,p->size,p->free);
		p = (char *)p + p->size;
	}
	printf("\n");
	printf("the free list:\n");
	printf("block\t\tnext\t\tsize\tfree\n");
	p = free_list;
	while (p != 0) {
		printf("%d\t%11d\t%d\t%d\n",p,p->next,p->size,p->free);
		p = p->next;
	}
	printf("\n");
	return 0;
}
