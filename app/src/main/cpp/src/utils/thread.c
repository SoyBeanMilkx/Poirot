#define _GNU_SOURCE

#include "thread.h"

#include <errno.h>
#include <sched.h>

int thread_choose_cpus(int *first, int *second) {
	cpu_set_t set;
	int found = 0;
	int cpu;

	if (!first || !second)
		return -EINVAL;
	if (sched_getaffinity(0, sizeof(set), &set) != 0)
		return -errno;

	*first = -1;
	*second = -1;
	for (cpu = 0; cpu < CPU_SETSIZE && found < 2; ++cpu) {
		if (!CPU_ISSET(cpu, &set))
			continue;
		if (!found)
			*first = cpu;
		else
			*second = cpu;
		++found;
	}

	if (!found)
		return -ENODEV;
	if (found == 1)
		*second = *first;
	return 0;
}

int thread_pin(int cpu) {
	cpu_set_t set;

	if (cpu < 0)
		return -EINVAL;
	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	return sched_setaffinity(0, sizeof(set), &set) == 0 ? 0 : -errno;
}
