#ifndef POIROT_CORE_PROBES_PROTECT_H
#define POIROT_CORE_PROBES_PROTECT_H

#include "poirot.h"

int poirot_protect_probe(const struct poirot_target *target,
			 const struct poirot_options *options, size_t page_size,
			 struct poirot_protect_result *result);

#endif
