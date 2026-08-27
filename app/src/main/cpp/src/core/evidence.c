#include "evidence.h"

static int evidence_status_incomplete(enum poirot_probe_status status) {
	return status == POIROT_PROBE_ERROR ||
	       status == POIROT_PROBE_INCONCLUSIVE;
}

static void evidence_account(enum poirot_probe_status status, int *completed,
			     int *incomplete) {
	if (status == POIROT_PROBE_CLEAN ||
	    status == POIROT_PROBE_SUSPICIOUS)
		++*completed;
	if (evidence_status_incomplete(status))
		*incomplete = 1;
}

static uint32_t evidence_shadow_checks(
	const struct poirot_shadow_report *shadow) {
	uint32_t checks = 0;

	if (shadow->timing.status == POIROT_PROBE_SUSPICIOUS)
		checks |= POIROT_CHECK_TIMING;
	if (shadow->selfread_result.status == POIROT_PROBE_SUSPICIOUS)
		checks |= POIROT_CHECK_SELFREAD;
	if (shadow->protect.status == POIROT_PROBE_SUSPICIOUS)
		checks |= POIROT_CHECK_PROTECT;
	if (shadow->parallel.status == POIROT_PROBE_SUSPICIOUS)
		checks |= POIROT_CHECK_PARALLEL;
	if (shadow->fork_result.status == POIROT_PROBE_SUSPICIOUS)
		checks |= POIROT_CHECK_FORK;
	return checks;
}

static uint32_t evidence_redirect_checks(
	const struct poirot_redirect_report *redirect) {
	uint32_t checks = 0;

	if ((redirect->checks & POIROT_CHECK_REDIRECT_FAULT) &&
	    redirect->fault.status == POIROT_PROBE_SUSPICIOUS)
		checks |= POIROT_CHECK_REDIRECT_FAULT;
	if ((redirect->checks & POIROT_CHECK_REDIRECT_SIGNAL) &&
	    redirect->signal.status == POIROT_PROBE_SUSPICIOUS)
		checks |= POIROT_CHECK_REDIRECT_SIGNAL;
	if ((redirect->checks & POIROT_CHECK_REDIRECT_GHOST) &&
	    redirect->ghost.status == POIROT_PROBE_SUSPICIOUS)
		checks |= POIROT_CHECK_REDIRECT_GHOST;
	return checks;
}

void evidence_evaluate(struct poirot_report *report) {
	int incomplete = 0;
	int completed = 0;

	if (!report)
		return;
	report->shadow.suspicious_checks =
		evidence_shadow_checks(&report->shadow);
	report->shadow.suspicious_count =
		poirot_hook_hit_count(report->shadow.suspicious_checks);
	report->redirect.suspicious_checks =
		evidence_redirect_checks(&report->redirect);
	report->redirect.suspicious_count =
		poirot_hook_hit_count(report->redirect.suspicious_checks);
	report->detected_mechanisms = 0;
	if (report->shadow.suspicious_count >= POIROT_DETECTION_MIN_HITS)
		report->detected_mechanisms |= POIROT_MECHANISM_SHADOW;
	if (report->redirect.status == POIROT_PROBE_SUSPICIOUS)
		report->detected_mechanisms |= POIROT_MECHANISM_REDIRECT;

	evidence_account(report->shadow.timing.status, &completed, &incomplete);
	evidence_account(report->shadow.selfread_result.status, &completed,
			 &incomplete);
	evidence_account(report->shadow.parallel.status, &completed, &incomplete);
	evidence_account(report->shadow.fork_result.status, &completed,
			 &incomplete);
	evidence_account(report->shadow.protect.status, &completed, &incomplete);
	evidence_account(report->redirect.status, &completed, &incomplete);

	if (report->detected_mechanisms)
		report->verdict = POIROT_VERDICT_DETECTED;
	else if (report->shadow.suspicious_count)
		report->verdict = POIROT_VERDICT_ANOMALOUS;
	else if (!completed || incomplete)
		report->verdict = POIROT_VERDICT_INCONCLUSIVE;
	else
		report->verdict = POIROT_VERDICT_CLEAN;
}
