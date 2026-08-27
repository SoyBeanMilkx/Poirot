#ifndef POIROT_CORE_REDIRECT_PROBES_GHOST_H
#define POIROT_CORE_REDIRECT_PROBES_GHOST_H

#include "poirot.h"

int redirect_ghost_probe(uintptr_t address, size_t page_size,
			 const struct poirot_options *options,
			 struct poirot_redirect_ghost_result *result);

#endif
