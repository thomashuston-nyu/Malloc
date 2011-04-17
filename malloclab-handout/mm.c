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
	"???@nyu.edu"
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
} header_t;


/* 
 * mm_init - initialize the malloc package.
 */
int mm_init(void) {
	return 0;
}

/* 
 * mm_malloc - Allocate a block by incrementing the brk pointer.
 *     Always allocate a block whose size is a multiple of the alignment.
 */
void *mm_malloc(size_t size) {
	if (size <= 0)
		return;
	size_t heapsize = mem_heapsize();
	int newsize = ALIGN(size + SIZE_T_SIZE);
	printf("size: %d\n",newsize);
	header_t *p;
	if (!heapsize) {
		p = mem_sbrk(newsize);
	} else {
		char *top = (char *)mem_heap_hi();
		p = mem_heap_lo();
		mm_check();
		while (p->size != 0 && p->size < (newsize - SIZE_T_SIZE) && p->free != 1) { // need to add a better check to see if at the end of the heap
//			printf("old: %d %d %d\n",top,p,p->size);
			p = (char *)p + p->size;
//			printf("new: %d %d %d\n",top,p,p->size);
		}
		if (p->free != 1)
			p = mem_sbrk(newsize);
	}
	if (p == (void *)-1)
		return NULL;
	else {
		p->size = newsize;
		p->free = 0;
		return (void *)((char *)p + SIZE_T_SIZE);
	}
}

/*
 * mm_free - Freeing a block does nothing.
 */
void mm_free(void *ptr) {
	ptr = (char *)(ptr) - SIZE_T_SIZE;
	((header_t *)(ptr))->free = 1;
	mm_check();
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
	return 0;
}
