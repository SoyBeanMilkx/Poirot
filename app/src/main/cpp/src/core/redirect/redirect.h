#ifndef POIROT_CORE_REDIRECT_H
#define POIROT_CORE_REDIRECT_H

#include "poirot.h"

int redirect_detect(const struct poirot_target *target,
		    const struct poirot_options *options,
		    struct poirot_report *report);

#endif
