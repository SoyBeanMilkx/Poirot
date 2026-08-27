#ifndef POIROT_CORE_SHADOW_H
#define POIROT_CORE_SHADOW_H

#include "poirot.h"

int shadow_detect(const struct poirot_target *target,
		  const struct poirot_options *options,
		  struct poirot_report *report);

#endif
