#ifndef POIROT_CORE_REDIRECT_PROBES_FAULT_H
#define POIROT_CORE_REDIRECT_PROBES_FAULT_H

#include "poirot.h"

int redirect_fault_probe(poirot_probe_fn function,
			 struct poirot_redirect_fault_result *result);

#endif
