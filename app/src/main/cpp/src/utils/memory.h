#ifndef POIROT_UTILS_MEMORY_H
#define POIROT_UTILS_MEMORY_H

#include <stddef.h>
#include <stdint.h>

struct poirot_memory_region {
	uintptr_t start;
	uintptr_t end;
	int prot;
};

size_t poirot_memory_page_size(void);
uintptr_t poirot_memory_page_start(uintptr_t address, size_t page_size);
int poirot_memory_query(uintptr_t address, struct poirot_memory_region *region);
uint64_t poirot_memory_hash(const void *data, size_t size);
size_t poirot_memory_diff(const void *left, const void *right, size_t size,
			  size_t *first_difference);

#endif
