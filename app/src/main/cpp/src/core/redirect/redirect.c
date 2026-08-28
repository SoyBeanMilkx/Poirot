#include "redirect.h"

#include "probes/fault.h"
#include "probes/ghost.h"
#include "probes/signal.h"
#include "src/utils/memory.h"

#include <errno.h>

static void redirect_error(enum poirot_probe_status *status, int *destination,
			   int error) {
	*status = POIROT_PROBE_ERROR;
	*destination = error < 0 ? -error : error;
}

static enum poirot_probe_status redirect_status(
	const struct poirot_redirect_report *redirect) {
	enum poirot_probe_status status = POIROT_PROBE_CLEAN;
	const enum poirot_probe_status values[] = {
		redirect->fault.status,
		redirect->signal.status,
		redirect->ghost.status,
	};
	const uint32_t checks[] = {
		POIROT_CHECK_REDIRECT_FAULT,
		POIROT_CHECK_REDIRECT_SIGNAL,
		POIROT_CHECK_REDIRECT_GHOST,
	};
	size_t i;

	for (i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {
		if (!(redirect->checks & checks[i]))
			continue;
		if (values[i] == POIROT_PROBE_SUSPICIOUS)
			return POIROT_PROBE_SUSPICIOUS;
		if (values[i] == POIROT_PROBE_ERROR)
			status = POIROT_PROBE_ERROR;
		else if (values[i] == POIROT_PROBE_INCONCLUSIVE &&
			 status != POIROT_PROBE_ERROR)
			status = POIROT_PROBE_INCONCLUSIVE;
	}
	return status;
}

int redirect_detect(const struct poirot_target *target,
		    const struct poirot_options *options,
		    struct poirot_report *report) {
	struct poirot_redirect_report *redirect;
	uintptr_t candidate = 0;
	uint32_t checks;
	int error;

	if (!target || !options || !report)
		return -EINVAL;

	redirect = &report->redirect;
	redirect->status = POIROT_PROBE_SKIPPED;
	redirect->fault.status = POIROT_PROBE_SKIPPED;
	redirect->signal.status = POIROT_PROBE_SKIPPED;
	redirect->ghost.status = POIROT_PROBE_SKIPPED;
	checks = options->checks & POIROT_CHECK_REDIRECT_ALL;
	redirect->checks = checks;
	if (!checks)
		return 0;

	if (checks & (POIROT_CHECK_REDIRECT_FAULT |
		      POIROT_CHECK_REDIRECT_GHOST)) {
		if (!target->fault ||
		    memory_page_start((uintptr_t)target->fault,
					     report->page_size) !=
			    report->target_page) {
			redirect_error(&redirect->fault.status,
				       &redirect->fault.error, EINVAL);
		} else {
			error = redirect_fault_probe(target->fault,
						    &redirect->fault);
			if (error)
				redirect_error(&redirect->fault.status,
					       &redirect->fault.error, error);
		}
	}

	if (checks & POIROT_CHECK_REDIRECT_SIGNAL) {
		if (!target->redirect ||
		    memory_page_start((uintptr_t)target->redirect,
					     report->page_size) !=
			    report->target_page) {
			redirect_error(&redirect->signal.status,
				       &redirect->signal.error, EINVAL);
		} else {
			error = redirect_signal_probe(
				target->redirect, options, report->page_size,
				&redirect->signal);
			if (error)
				redirect_error(&redirect->signal.status,
					       &redirect->signal.error, error);
		}
	}

	if (redirect->fault.status == POIROT_PROBE_SUSPICIOUS)
		candidate = redirect->fault.pc;
	else if (redirect->signal.first_unmapped_pc)
		candidate = redirect->signal.first_unmapped_pc;

	if (checks & POIROT_CHECK_REDIRECT_GHOST) {
		if (!candidate) {
			redirect->ghost.status =
				redirect->fault.status == POIROT_PROBE_CLEAN
					? POIROT_PROBE_CLEAN
					: POIROT_PROBE_INCONCLUSIVE;
		} else {
			error = redirect_ghost_probe(
				candidate, report->page_size, options,
				&redirect->ghost);
			if (error)
				redirect_error(&redirect->ghost.status,
					       &redirect->ghost.error, error);
		}
	}

	redirect->status = redirect_status(redirect);
	return 0;
}
