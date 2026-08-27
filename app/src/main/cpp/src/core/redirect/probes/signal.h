#ifndef POIROT_CORE_REDIRECT_PROBES_SIGNAL_H
#define POIROT_CORE_REDIRECT_PROBES_SIGNAL_H

#include "poirot.h"

int redirect_signal_probe(poirot_probe_fn function,
			  const struct poirot_options *options,
			  size_t page_size,
			  struct poirot_redirect_signal_result *result);

#endif
