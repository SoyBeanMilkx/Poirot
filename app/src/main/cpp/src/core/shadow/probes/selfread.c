#include "src/core/shadow/probes/selfread.h"

#include "src/utils/timeout.h"

#include <errno.h>

int selfread_probe(const struct poirot_target *target,
		   const struct poirot_options *options,
		   struct poirot_selfread_result *result) {
	struct poirot_timeout_result call;
	int error;

	if (!target || !target->selfread || !options || !result)
		return -EINVAL;

	error = timeout_call(target->selfread,
				    options->selfread_timeout_ms, &call);
	if (error)
		return error;

	result->elapsed_ns = call.elapsed_ns;
	result->value = call.value;
	result->timed_out = call.timed_out;
	result->status =
		call.timed_out || call.value != target->selfread_expected
			? POIROT_PROBE_SUSPICIOUS
			: POIROT_PROBE_CLEAN;
	return 0;
}
