#ifndef POIROT_CORE_SHADOW_PROBES_FORK_H
#define POIROT_CORE_SHADOW_PROBES_FORK_H

#include "poirot.h"

int fork_probe(const struct poirot_target *target,
	       const struct poirot_options *options,
	       struct poirot_fork_result *result);

#endif
