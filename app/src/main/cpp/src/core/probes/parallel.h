#ifndef POIROT_CORE_PROBES_PARALLEL_H
#define POIROT_CORE_PROBES_PARALLEL_H

#include "poirot.h"

int poirot_parallel_probe(const struct poirot_target *target,
			  const struct poirot_options *options,
			  struct poirot_parallel_result *result);

#endif
