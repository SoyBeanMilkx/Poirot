#include "src/core/shadow/probes/protect.h"

#include "src/utils/memory.h"

#include <errno.h>
#include <stdlib.h>
#include <sys/mman.h>

static void protect_copy_page(unsigned char *destination,
			      const volatile unsigned char *source,
			      size_t size) {
	size_t i;

	for (i = 0; i < size; ++i)
		destination[i] = source[i];
}

int protect_probe(const struct poirot_target *target,
		  const struct poirot_options *options, size_t page_size,
		  struct poirot_protect_result *result) {
	struct poirot_memory_region region;
	volatile const unsigned char *page;
	unsigned char *original;
	unsigned char *exposed;
	uintptr_t page_address;
	int error;

	if (!target || !target->target || !target->activate || !options ||
	    !result || !page_size)
		return -EINVAL;
	if (!options->allow_intrusive) {
		result->status = POIROT_PROBE_SKIPPED;
		return 0;
	}

	page_address =
		memory_page_start((uintptr_t)target->target, page_size);
	error = memory_query(page_address, &region);
	if (error)
		return error;
	result->original_prot = region.prot;
	if (region.start > page_address ||
	    region.end < page_address + page_size ||
	    (region.prot & (PROT_READ | PROT_EXEC)) !=
		    (PROT_READ | PROT_EXEC) ||
	    (region.prot & PROT_WRITE)) {
		result->status = POIROT_PROBE_INCONCLUSIVE;
		result->error = EOPNOTSUPP;
		return 0;
	}

	original = malloc(page_size);
	exposed = malloc(page_size);
	if (!original || !exposed) {
		free(original);
		free(exposed);
		return -ENOMEM;
	}
	page = (volatile const unsigned char *)page_address;

	/* Read first to select the clean PFN. The unhooked same-page anchor then
	 * selects shadow without running target hook callbacks. */
	protect_copy_page(original, page, page_size);
	(void)target->activate(UINT64_C(0x50524f54));
	if (mprotect((void *)page_address, page_size, PROT_READ) != 0) {
		error = -errno;
		free(original);
		free(exposed);
		return error;
	}
	protect_copy_page(exposed, page, page_size);
	if (mprotect((void *)page_address, page_size, region.prot) != 0)
		result->restore_error = errno;

	result->original_hash = memory_hash(original, page_size);
	result->exposed_hash = memory_hash(exposed, page_size);
	result->different_bytes = memory_diff(
		original, exposed, page_size, &result->first_difference);
	result->status = result->restore_error	   ? POIROT_PROBE_ERROR
			 : result->different_bytes ? POIROT_PROBE_SUSPICIOUS
						   : POIROT_PROBE_CLEAN;
	free(original);
	free(exposed);
	return 0;
}
