#ifndef POIROT_CORE_SHADOW_PROBES_TIMING_H
#define POIROT_CORE_SHADOW_PROBES_TIMING_H

#include "poirot.h"

int timing_probe(const struct poirot_target *target,
		 const struct poirot_options *options,
		 struct poirot_timing_result *result);

#endif
