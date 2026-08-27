#include "shadow.h"

#include "src/core/shadow/probes/fork.h"
#include "src/core/shadow/probes/parallel.h"
#include "src/core/shadow/probes/protect.h"
#include "src/core/shadow/probes/selfread.h"
#include "src/core/shadow/probes/timing.h"
#include "src/utils/memory.h"

#include <errno.h>

static void shadow_error(enum poirot_probe_status *status, int *destination,
			 int error) {
	*status = POIROT_PROBE_ERROR;
	*destination = error < 0 ? -error : error;
}

int shadow_detect(const struct poirot_target *target,
		  const struct poirot_options *options,
		  struct poirot_report *report) {
	struct poirot_shadow_report *shadow;
	uintptr_t control_page = 0;
	uintptr_t selfread_page = 0;
	int error;

	if (!target || !options || !report)
		return -EINVAL;
	shadow = &report->shadow;
	shadow->timing.status = POIROT_PROBE_SKIPPED;
	shadow->selfread_result.status = POIROT_PROBE_SKIPPED;
	shadow->parallel.status = POIROT_PROBE_SKIPPED;
	shadow->fork_result.status = POIROT_PROBE_SKIPPED;
	shadow->protect.status = POIROT_PROBE_SKIPPED;
	if (target->control)
		control_page = memory_page_start(
			(uintptr_t)target->control, report->page_size);
	if (target->selfread)
		selfread_page = memory_page_start(
			(uintptr_t)target->selfread, report->page_size);

	if (options->checks & POIROT_CHECK_TIMING) {
		if (!target->control || control_page == report->target_page) {
			shadow_error(&shadow->timing.status,
				     &shadow->timing.error, EINVAL);
		} else {
			error = timing_probe(target, options,
						    &shadow->timing);
			if (error)
				shadow_error(&shadow->timing.status,
					     &shadow->timing.error, error);
		}
	}

	if (options->checks & POIROT_CHECK_SELFREAD) {
		if (!target->selfread || selfread_page != report->target_page) {
			shadow_error(&shadow->selfread_result.status,
				     &shadow->selfread_result.error, EINVAL);
		} else {
			error = selfread_probe(target, options,
						      &shadow->selfread_result);
			if (error)
				shadow_error(&shadow->selfread_result.status,
					     &shadow->selfread_result.error,
					     error);
		}
	}

	if (options->checks & POIROT_CHECK_PARALLEL) {
		if (!target->control || control_page == report->target_page) {
			shadow_error(&shadow->parallel.status,
				     &shadow->parallel.error, EINVAL);
		} else {
			error = parallel_probe(target, options,
						      &shadow->parallel);
			if (error)
				shadow_error(&shadow->parallel.status,
					     &shadow->parallel.error, error);
		}
	}

	if (options->checks & POIROT_CHECK_FORK) {
		error = fork_probe(target, options,
					  &shadow->fork_result);
		if (error)
			shadow_error(&shadow->fork_result.status,
				     &shadow->fork_result.error, error);
	}

	/* Permission rebuilding changes the target page and must remain last. */
	if (options->checks & POIROT_CHECK_PROTECT) {
		if (!target->activate ||
		    memory_page_start((uintptr_t)target->activate,
					     report->page_size) !=
			    report->target_page) {
			shadow_error(&shadow->protect.status,
				     &shadow->protect.error, EINVAL);
		} else {
			error = protect_probe(target, options,
						     report->page_size,
						     &shadow->protect);
			if (error)
				shadow_error(&shadow->protect.status,
					     &shadow->protect.error, error);
		}
	}
	return 0;
}
