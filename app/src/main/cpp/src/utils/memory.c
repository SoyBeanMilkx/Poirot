#include "memory.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

size_t poirot_memory_page_size(void) {
	long value = sysconf(_SC_PAGESIZE);

	return value > 0 ? (size_t)value : 0;
}

uintptr_t poirot_memory_page_start(uintptr_t address, size_t page_size) {
	if (!page_size)
		return 0;
	return address - address % page_size;
}

int poirot_memory_query(uintptr_t address,
			struct poirot_memory_region *region) {
	char line[512];
	FILE *maps;

	if (!region)
		return -EINVAL;

	maps = fopen("/proc/self/maps", "re");
	if (!maps)
		return -errno;

	while (fgets(line, sizeof(line), maps)) {
		unsigned long long start;
		unsigned long long end;
		char permissions[5] = {0};

		if (sscanf(line, "%llx-%llx %4s", &start, &end, permissions) !=
		    3)
			continue;
		if (address < (uintptr_t)start || address >= (uintptr_t)end)
			continue;

		region->start = (uintptr_t)start;
		region->end = (uintptr_t)end;
		region->prot = 0;
		if (permissions[0] == 'r')
			region->prot |= PROT_READ;
		if (permissions[1] == 'w')
			region->prot |= PROT_WRITE;
		if (permissions[2] == 'x')
			region->prot |= PROT_EXEC;
		fclose(maps);
		return 0;
	}

	fclose(maps);
	return -ENOENT;
}

uint64_t poirot_memory_hash(const void *data, size_t size) {
	const unsigned char *bytes = data;
	uint64_t hash = UINT64_C(14695981039346656037);
	size_t i;

	for (i = 0; i < size; ++i) {
		hash ^= bytes[i];
		hash *= UINT64_C(1099511628211);
	}

	return hash;
}

size_t poirot_memory_diff(const void *left, const void *right, size_t size,
			  size_t *first_difference) {
	const unsigned char *a = left;
	const unsigned char *b = right;
	size_t first = SIZE_MAX;
	size_t count = 0;
	size_t i;

	for (i = 0; i < size; ++i) {
		if (a[i] == b[i])
			continue;
		if (first == SIZE_MAX)
			first = i;
		++count;
	}

	if (first_difference)
		*first_difference = first;
	return count;
}
