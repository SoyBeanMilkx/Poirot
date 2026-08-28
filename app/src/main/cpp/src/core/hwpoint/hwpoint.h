#ifndef POIROT_CORE_HWPOINT_H
#define POIROT_CORE_HWPOINT_H

#include "poirot.h"

#define HWPOINT_SLOT_CAPACITY 16u
#define HWPOINT_PROBE_ROUNDS 2u

int hwpoint_detect(const struct poirot_options *options,
		   struct poirot_report *report);

#endif
