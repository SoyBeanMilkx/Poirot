#ifndef POIROT_UTILS_TIMEOUT_H
#define POIROT_UTILS_TIMEOUT_H

#include <stdint.h>

typedef uint64_t (*poirot_timeout_fn)(void);

struct poirot_timeout_result {
	uint64_t value;
	uint64_t elapsed_ns;
	int timed_out;
};

int poirot_timeout_call(poirot_timeout_fn function, uint32_t timeout_ms,
			struct poirot_timeout_result *result);

#endif
