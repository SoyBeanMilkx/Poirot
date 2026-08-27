#include "src/core/probes/timing.h"

#include "src/utils/time.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>

static volatile uint64_t timing_sink;

static uint32_t timing_ratio(uint64_t numerator, uint64_t denominator) {
	__uint128_t scaled;

	if (!denominator)
		return UINT32_MAX;
	scaled = (__uint128_t)numerator * 1000u / denominator;
	return scaled > UINT32_MAX ? UINT32_MAX : (uint32_t)scaled;
}

static uint64_t timing_batch(poirot_probe_fn function, uint32_t iterations) {
	volatile const uint32_t *instruction =
		(volatile const uint32_t *)(uintptr_t)function;
	uint64_t accumulator = 0;
	uint64_t started;
	uint32_t i;

	started = poirot_time_now_ns();
	for (i = 0; i < iterations; ++i)
		accumulator += *instruction;
	for (i = 0; i < iterations; ++i)
		accumulator += function(i);
	timing_sink = accumulator;
	return poirot_time_now_ns() - started;
}

static uint64_t timing_alternating(poirot_probe_fn function,
				   uint32_t iterations) {
	volatile const uint32_t *instruction =
		(volatile const uint32_t *)(uintptr_t)function;
	uint64_t accumulator = 0;
	uint64_t started;
	uint32_t i;

	started = poirot_time_now_ns();
	for (i = 0; i < iterations; ++i) {
		accumulator += *instruction;
		accumulator += function(i);
	}
	timing_sink = accumulator;
	return poirot_time_now_ns() - started;
}

int poirot_timing_probe(const struct poirot_target *target,
			const struct poirot_options *options,
			struct poirot_timing_result *result) {
	uint64_t *samples;
	uint64_t target_delta;
	uint64_t control_delta;
	int call_suspicious;
	int switch_suspicious;
	uint32_t rounds;
	uint32_t i;

	if (!target || !target->target || !target->control || !options ||
	    !result)
		return -EINVAL;
	if (!options->timing_iterations || !options->timing_rounds ||
	    options->timing_rounds > 31)
		return -EINVAL;

	rounds = options->timing_rounds;
	samples = calloc((size_t)rounds * 4, sizeof(*samples));
	if (!samples)
		return -ENOMEM;

	(void)*(volatile const uint32_t *)(uintptr_t)target->target;
	(void)target->target(1);
	(void)*(volatile const uint32_t *)(uintptr_t)target->control;
	(void)target->control(1);

	for (i = 0; i < rounds; ++i) {
		if (!(i & 1)) {
			samples[i] = timing_batch(target->target,
						  options->timing_iterations);
			samples[rounds + i] = timing_alternating(
				target->target, options->timing_iterations);
			samples[rounds * 2 + i] = timing_batch(
				target->control, options->timing_iterations);
			samples[rounds * 3 + i] = timing_alternating(
				target->control, options->timing_iterations);
		} else {
			samples[rounds + i] = timing_alternating(
				target->target, options->timing_iterations);
			samples[i] = timing_batch(target->target,
						  options->timing_iterations);
			samples[rounds * 3 + i] = timing_alternating(
				target->control, options->timing_iterations);
			samples[rounds * 2 + i] = timing_batch(
				target->control, options->timing_iterations);
		}
	}

	result->batch_ns = poirot_time_median(samples, rounds);
	result->alternating_ns = poirot_time_median(samples + rounds, rounds);
	result->control_batch_ns =
		poirot_time_median(samples + rounds * 2, rounds);
	result->control_alternating_ns =
		poirot_time_median(samples + rounds * 3, rounds);
	free(samples);

	result->ratio_permille =
		timing_ratio(result->alternating_ns, result->batch_ns);
	result->target_control_ratio_permille =
		timing_ratio(result->batch_ns, result->control_batch_ns);
	target_delta = result->alternating_ns > result->batch_ns
			       ? result->alternating_ns - result->batch_ns
			       : 0;
	control_delta =
		result->control_alternating_ns > result->control_batch_ns
			? result->control_alternating_ns -
				  result->control_batch_ns
			: 0;
	result->excess_per_iteration_ns =
		target_delta > control_delta
			? (target_delta - control_delta) /
				  options->timing_iterations
			: 0;
	result->call_excess_per_iteration_ns =
		result->batch_ns > result->control_batch_ns
			? (result->batch_ns - result->control_batch_ns) /
				  options->timing_iterations
			: 0;
	switch_suspicious =
		result->ratio_permille >= options->timing_ratio_permille &&
		result->excess_per_iteration_ns >=
			options->timing_min_excess_ns;
	call_suspicious =
		result->target_control_ratio_permille >=
			options->timing_ratio_permille &&
		result->call_excess_per_iteration_ns >=
			options->timing_min_excess_ns;
	result->status = switch_suspicious || call_suspicious
			 ? POIROT_PROBE_SUSPICIOUS
			 : POIROT_PROBE_CLEAN;
	return 0;
}
