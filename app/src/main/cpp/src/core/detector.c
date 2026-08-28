#include "poirot.h"

#include "evidence.h"
#include "hwpoint/hwpoint.h"
#include "redirect/redirect.h"
#include "shadow/shadow.h"
#include "src/utils/memory.h"

#include <errno.h>
#include <string.h>

void poirot_options_default(struct poirot_options *options) {
	if (!options)
		return;
	*options = (struct poirot_options){
		.checks = POIROT_CHECK_DIAGNOSTIC,
		.timing_iterations = 3000,
		.timing_rounds = 5,
		.selfread_timeout_ms = 150,
		.parallel_iterations = 3000,
		.fork_timeout_ms = 1000,
		.redirect_samples = 48,
		.redirect_timeout_ms = 750,
		.timing_ratio_permille = 1800,
		.parallel_ratio_permille = 2200,
		.timing_min_excess_ns = 300,
		.parallel_min_excess_ns = 300,
		.allow_intrusive = 1,
	};
}

int poirot_detect(const struct poirot_target *target,
		  const struct poirot_options *options,
		  struct poirot_report *report) {
	int error;

	if (!target || !target->target || !options || !report)
		return -EINVAL;
	memset(report, 0, sizeof(*report));
	report->page_size = memory_page_size();
	if (!report->page_size)
		return -ENOSYS;
	report->target = (uintptr_t)target->target;
	report->target_page = memory_page_start(report->target, report->page_size);
	report->control = (uintptr_t)target->control;
	report->activate = (uintptr_t)target->activate;
	report->selfread = (uintptr_t)target->selfread;
	report->redirect_target = (uintptr_t)target->redirect;
	report->fault_target = (uintptr_t)target->fault;

	error = hwpoint_detect(options, report);
	if (error)
		return error;
	error = redirect_detect(target, options, report);
	if (error)
		return error;
	error = shadow_detect(target, options, report);
	if (error)
		return error;
	evidence_evaluate(report);
	return 0;
}
