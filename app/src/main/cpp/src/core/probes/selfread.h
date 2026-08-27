#ifndef POIROT_CORE_PROBES_SELFREAD_H
#define POIROT_CORE_PROBES_SELFREAD_H

#include "poirot.h"

int poirot_selfread_probe(const struct poirot_target *target,
			  const struct poirot_options *options,
			  struct poirot_selfread_result *result);

#endif
