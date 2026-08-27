#include "time.h"

#include <time.h>

uint64_t poirot_time_now_ns(void) {
	struct timespec value;

	if (clock_gettime(CLOCK_MONOTONIC, &value) != 0)
		return 0;

	return (uint64_t)value.tv_sec * UINT64_C(1000000000) +
	       (uint64_t)value.tv_nsec;
}

uint64_t poirot_time_median(uint64_t *values, size_t count) {
	size_t i;

	if (!values || !count)
		return 0;

	for (i = 1; i < count; ++i) {
		uint64_t value = values[i];
		size_t j = i;

		while (j && values[j - 1] > value) {
			values[j] = values[j - 1];
			--j;
		}
		values[j] = value;
	}

	return values[count / 2];
}
