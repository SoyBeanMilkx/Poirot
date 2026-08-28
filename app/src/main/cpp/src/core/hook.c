#include "poirot.h"

#include "hook.h"

static uint64_t hook_expected(uint64_t input, void *context) {
	(void)context;
	return input + POIROT_HOOK_BIAS;
}

uint32_t poirot_hook_check_site(uint32_t checks, poirot_probe_fn target,
				poirot_canary_fn selfread,
				poirot_probe_fn redirect,
				poirot_probe_fn fault) {
	struct poirot_options options;
	struct poirot_target site;
	struct poirot_report report;

	checks &= POIROT_CHECK_ALL;
	if (!checks || !target)
		return 0;

	poirot_options_default(&options);
	options.checks = checks;
	site = (struct poirot_target){
		.target = target,
		.control = hook_control,
		.activate = target,
		.selfread = selfread,
		.redirect = redirect,
		.fault = fault,
		.expected = hook_expected,
		.expected_context = NULL,
		.selfread_expected = POIROT_HOOK_CANARY,
	};
	if (poirot_detect(&site, &options, &report) != 0)
		return 0;
	return (report.shadow.suspicious_checks |
		report.redirect.suspicious_checks |
		(report.hwpoint.status == POIROT_PROBE_SUSPICIOUS
			 ? POIROT_CHECK_HWPOINT
			 : 0)) &
	       checks;
}
