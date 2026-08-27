#include "poirot.h"

#include "src/core/probes/fork.h"
#include "src/core/probes/parallel.h"
#include "src/core/probes/protect.h"
#include "src/core/probes/selfread.h"
#include "src/core/probes/timing.h"
#include "src/utils/memory.h"

#include <errno.h>
#include <string.h>

void poirot_options_default(struct poirot_options *options) {
	if (!options)
		return;
	*options = (struct poirot_options){
		.checks = POIROT_CHECK_TIMING |
			  /* POIROT_CHECK_SELFREAD | */
			  POIROT_CHECK_PROTECT | POIROT_CHECK_PARALLEL |
			  POIROT_CHECK_FORK,
		.timing_iterations = 3000,
		.timing_rounds = 5,
		.selfread_timeout_ms = 150,
		.parallel_iterations = 3000,
		.fork_timeout_ms = 1000,
		.timing_ratio_permille = 1800,
		.parallel_ratio_permille = 2200,
		.timing_min_excess_ns = 300,
		.parallel_min_excess_ns = 300,
		.allow_intrusive = 1,
	};
}

static void detector_error(enum poirot_probe_status *status, int *destination,
			   int error) {
	*status = POIROT_PROBE_ERROR;
	*destination = error < 0 ? -error : error;
}

static int detector_status_incomplete(enum poirot_probe_status status) {
	return status == POIROT_PROBE_ERROR ||
	       status == POIROT_PROBE_INCONCLUSIVE;
}

static uint32_t detector_suspicious_checks(const struct poirot_report *report) {
	uint32_t checks = 0;

	if (report->timing.status == POIROT_PROBE_SUSPICIOUS)
		checks |= POIROT_CHECK_TIMING;
	if (report->selfread_result.status == POIROT_PROBE_SUSPICIOUS)
		checks |= POIROT_CHECK_SELFREAD;
	if (report->protect.status == POIROT_PROBE_SUSPICIOUS)
		checks |= POIROT_CHECK_PROTECT;
	if (report->parallel.status == POIROT_PROBE_SUSPICIOUS)
		checks |= POIROT_CHECK_PARALLEL;
	if (report->fork_result.status == POIROT_PROBE_SUSPICIOUS)
		checks |= POIROT_CHECK_FORK;
	return checks;
}

int poirot_detect(const struct poirot_target *target,
		  const struct poirot_options *options,
		  struct poirot_report *report) {
	uintptr_t control_page;
	uintptr_t selfread_page;
	int incomplete = 0;
	int completed = 0;
	int error;

	if (!target || !options || !report || !target->target ||
	    !target->control || !target->selfread || !target->expected)
		return -EINVAL;
	memset(report, 0, sizeof(*report));
	report->timing.status = POIROT_PROBE_SKIPPED;
	report->selfread_result.status = POIROT_PROBE_SKIPPED;
	report->parallel.status = POIROT_PROBE_SKIPPED;
	report->fork_result.status = POIROT_PROBE_SKIPPED;
	report->protect.status = POIROT_PROBE_SKIPPED;

	report->page_size = poirot_memory_page_size();
	if (!report->page_size)
		return -ENOSYS;
	report->target = (uintptr_t)target->target;
	report->target_page =
		poirot_memory_page_start(report->target, report->page_size);
	report->control = (uintptr_t)target->control;
	report->activate = (uintptr_t)target->activate;
	report->selfread = (uintptr_t)target->selfread;
	control_page =
		poirot_memory_page_start(report->control, report->page_size);
	selfread_page =
		poirot_memory_page_start(report->selfread, report->page_size);

	if (options->checks & POIROT_CHECK_TIMING) {
		if (control_page == report->target_page) {
			detector_error(&report->timing.status,
				       &report->timing.error, EINVAL);
		} else {
			error = poirot_timing_probe(target, options,
						    &report->timing);
			if (error)
				detector_error(&report->timing.status,
					       &report->timing.error, error);
		}
	}

	if (options->checks & POIROT_CHECK_SELFREAD) {
		if (selfread_page != report->target_page) {
			detector_error(&report->selfread_result.status,
				       &report->selfread_result.error, EINVAL);
		} else {
			error = poirot_selfread_probe(target, options,
						      &report->selfread_result);
			if (error)
				detector_error(&report->selfread_result.status,
					       &report->selfread_result.error,
					       error);
		}
	}

	if (options->checks & POIROT_CHECK_PARALLEL) {
		if (control_page == report->target_page) {
			detector_error(&report->parallel.status,
				       &report->parallel.error, EINVAL);
		} else {
			error = poirot_parallel_probe(target, options,
						      &report->parallel);
			if (error)
				detector_error(&report->parallel.status,
					       &report->parallel.error, error);
		}
	}

	if (options->checks & POIROT_CHECK_FORK) {
		error = poirot_fork_probe(target, options,
					  &report->fork_result);
		if (error)
			detector_error(&report->fork_result.status,
				       &report->fork_result.error, error);
	}

	/* This probe changes page permissions and must remain last. */
	if (options->checks & POIROT_CHECK_PROTECT) {
		if (!target->activate ||
		    poirot_memory_page_start(report->activate,
					     report->page_size) !=
			    report->target_page) {
			detector_error(&report->protect.status,
				       &report->protect.error, EINVAL);
		} else {
			error = poirot_protect_probe(target, options,
					     report->page_size,
					     &report->protect);
			if (error)
				detector_error(&report->protect.status,
					       &report->protect.error, error);
		}
	}

	report->suspicious_checks = detector_suspicious_checks(report);
	report->suspicious_count =
		poirot_hook_hit_count(report->suspicious_checks);

#define ACCOUNT_RESULT(value)                                                  \
	do {                                                                   \
		if ((value) == POIROT_PROBE_CLEAN ||                           \
		    (value) == POIROT_PROBE_SUSPICIOUS)                        \
			++completed;                                           \
		if (detector_status_incomplete(value))                         \
			incomplete = 1;                                        \
	} while (0)
	ACCOUNT_RESULT(report->timing.status);
	ACCOUNT_RESULT(report->selfread_result.status);
	ACCOUNT_RESULT(report->parallel.status);
	ACCOUNT_RESULT(report->fork_result.status);
	ACCOUNT_RESULT(report->protect.status);
#undef ACCOUNT_RESULT

	if (poirot_hook_hits_detected(report->suspicious_checks))
		report->verdict = POIROT_VERDICT_DETECTED;
	else if (report->suspicious_count)
		report->verdict = POIROT_VERDICT_ANOMALOUS;
	else if (!completed || incomplete)
		report->verdict = POIROT_VERDICT_INCONCLUSIVE;
	else
		report->verdict = POIROT_VERDICT_CLEAN;
	return 0;
}
