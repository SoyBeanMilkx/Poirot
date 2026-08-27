#ifndef POIROT_UTILS_TIME_H
#define POIROT_UTILS_TIME_H

#include <stddef.h>
#include <stdint.h>

uint64_t poirot_time_now_ns(void);
uint64_t poirot_time_median(uint64_t *values, size_t count);

#endif
