#ifndef POIROT_H
#define POIROT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define POIROT_CHECK_TIMING (UINT32_C(1) << 0)
#define POIROT_CHECK_SELFREAD (UINT32_C(1) << 1)
#define POIROT_CHECK_PROTECT (UINT32_C(1) << 2)
#define POIROT_CHECK_PARALLEL (UINT32_C(1) << 3)
#define POIROT_CHECK_FORK (UINT32_C(1) << 4)
#define POIROT_CHECK_REDIRECT_FAULT (UINT32_C(1) << 8)
#define POIROT_CHECK_REDIRECT_SIGNAL (UINT32_C(1) << 9)
#define POIROT_CHECK_REDIRECT_GHOST (UINT32_C(1) << 10)
#define POIROT_CHECK_HWPOINT (UINT32_C(1) << 16)
#define POIROT_CHECK_SHADOW_ALL                                           \
	(POIROT_CHECK_TIMING | POIROT_CHECK_SELFREAD | POIROT_CHECK_PROTECT | \
	 POIROT_CHECK_PARALLEL | POIROT_CHECK_FORK)
#define POIROT_CHECK_REDIRECT_ALL                                         \
	(POIROT_CHECK_REDIRECT_FAULT | POIROT_CHECK_REDIRECT_SIGNAL |        \
	 POIROT_CHECK_REDIRECT_GHOST)
#define POIROT_CHECK_HWPOINT_ALL POIROT_CHECK_HWPOINT
#define POIROT_CHECK_ALL                                                   \
	(POIROT_CHECK_SHADOW_ALL | POIROT_CHECK_REDIRECT_ALL |                \
	 POIROT_CHECK_HWPOINT_ALL)
#define POIROT_DETECTION_MIN_HITS UINT32_C(2)

#define POIROT_MECHANISM_SHADOW (UINT32_C(1) << 0)
#define POIROT_MECHANISM_REDIRECT (UINT32_C(1) << 1)
#define POIROT_MECHANISM_HWPOINT (UINT32_C(1) << 2)

#define POIROT_CHECK_SAFE POIROT_CHECK_TIMING

#define POIROT_CHECK_DIAGNOSTIC                                             \
	(POIROT_CHECK_TIMING | POIROT_CHECK_PROTECT | POIROT_CHECK_PARALLEL | \
	 POIROT_CHECK_FORK | POIROT_CHECK_REDIRECT_ALL |                       \
	 POIROT_CHECK_HWPOINT_ALL)

typedef uint64_t (*poirot_probe_fn)(uint64_t input);
typedef uint64_t (*poirot_canary_fn)(void);
typedef uint64_t (*poirot_expected_fn)(uint64_t input, void *context);

uint32_t poirot_hook_check_site(uint32_t checks, poirot_probe_fn target,
				poirot_canary_fn selfread,
				poirot_probe_fn redirect,
				poirot_probe_fn fault);

/*
 * Place this near the beginning of the function being protected. The macro
 * emits small probes into the containing code page, then runs only the
 * checks selected by the mask. A returned bit identifies the check that saw
 * evidence of a hook.
 *
 * The check is synchronous. It may be triggered explicitly, or placed in
 * normal business code to run whenever that path executes. The caller can
 * branch on the returned mask. Diagnostic checks are relatively expensive,
 * so applications should run them selectively or at a low frequency.
 *
 * POIROT_CHECK_SELFREAD is intentionally opt-in: a broken page-switching
 * implementation may trap indefinitely before the user-space timeout fires.
 */
#if defined(__aarch64__)
#define POIROT_HOOK_CHECK(checks)                                           \
	__extension__({                                                       \
		uintptr_t __poirot_target;                                     \
		uintptr_t __poirot_selfread;                                   \
		uintptr_t __poirot_redirect;                                   \
		uintptr_t __poirot_fault;                                      \
		__asm__ volatile(                                              \
			"b 9f\n"                                                \
			".balign 4\n"                                          \
			"1:\n"                                                 \
			".inst 0xd503245f\n" /* BTI c */                       \
			"add x0, x0, #17\n"                                   \
			"ret\n"                                                \
			".balign 4\n"                                          \
			"2:\n"                                                 \
			".inst 0xd503245f\n" /* BTI c */                       \
			"adr x9, 4f\n"                                         \
			"ldr x0, [x9]\n"                                      \
			"ret\n"                                                \
			".balign 8\n"                                          \
			"4:\n"                                                 \
			".quad 0x504f49524f54584a\n"                          \
			".balign 4\n"                                          \
			"5:\n"                                                 \
			".inst 0xd503245f\n" /* BTI c */                       \
			"mov w9, #4096\n"                                      \
			"6:\n"                                                 \
			"add x0, x0, #1\n"                                     \
			"subs w9, w9, #1\n"                                     \
			"b.ne 6b\n"                                             \
			"ret\n"                                                \
			".balign 4\n"                                          \
			"7:\n"                                                 \
			".inst 0xd503245f\n" /* BTI c */                       \
			"ldr x0, [x0]\n"                                      \
			"ret\n"                                                \
			"9:\n"                                                 \
			"adr %0, 1b\n"                                         \
			"adr %1, 2b\n"                                         \
			"adr %2, 5b\n"                                         \
			"adr %3, 7b\n"                                         \
			: "=r"(__poirot_target), "=r"(__poirot_selfread),     \
			  "=r"(__poirot_redirect), "=r"(__poirot_fault)       \
			:                                                        \
			: "memory");                                            \
		poirot_hook_check_site(                                     \
			(uint32_t)(checks),                                   \
			(poirot_probe_fn)(uintptr_t)__poirot_target,           \
			(poirot_canary_fn)(uintptr_t)__poirot_selfread,        \
			(poirot_probe_fn)(uintptr_t)__poirot_redirect,         \
			(poirot_probe_fn)(uintptr_t)__poirot_fault);           \
	})
#else
#define POIROT_HOOK_CHECK(checks) ((uint32_t)(checks) & UINT32_C(0))
#endif

static inline uint32_t poirot_hook_hit_count(uint32_t hits) {
	uint32_t count = 0;

	hits &= POIROT_CHECK_ALL;
	while (hits) {
		hits &= hits - 1u;
		++count;
	}
	return count;
}

static inline int poirot_hook_hits_detected(uint32_t hits) {
	if (hits & (POIROT_CHECK_REDIRECT_ALL | POIROT_CHECK_HWPOINT_ALL))
		return 1;
	return poirot_hook_hit_count(hits & POIROT_CHECK_SHADOW_ALL) >=
	       POIROT_DETECTION_MIN_HITS;
}

#define POIROT_HOOK_DETECTED(checks)                                      \
	poirot_hook_hits_detected(POIROT_HOOK_CHECK(checks))

enum poirot_probe_status {
	POIROT_PROBE_SKIPPED = 0,
	POIROT_PROBE_CLEAN,
	POIROT_PROBE_SUSPICIOUS,
	POIROT_PROBE_INCONCLUSIVE,
	POIROT_PROBE_ERROR,
};

enum poirot_verdict {
	POIROT_VERDICT_CLEAN = 0,
	POIROT_VERDICT_ANOMALOUS,
	POIROT_VERDICT_DETECTED,
	POIROT_VERDICT_INCONCLUSIVE,
};

struct poirot_target {
	/* control has the same semantics on another page; selfread shares
	 * target's page. */
	poirot_probe_fn target;
	poirot_probe_fn control;
	/* Unhooked execution anchor on target's page. */
	poirot_probe_fn activate;
	poirot_canary_fn selfread;
	poirot_probe_fn redirect;
	poirot_probe_fn fault;
	poirot_expected_fn expected;
	void *expected_context;
	uint64_t selfread_expected;
};

struct poirot_options {
	uint32_t checks;
	uint32_t timing_iterations;
	uint32_t timing_rounds;
	uint32_t selfread_timeout_ms;
	uint32_t parallel_iterations;
	uint32_t fork_timeout_ms;
	uint32_t redirect_samples;
	uint32_t redirect_timeout_ms;
	uint32_t timing_ratio_permille;
	uint32_t parallel_ratio_permille;
	uint64_t timing_min_excess_ns;
	uint64_t parallel_min_excess_ns;
	/* Permission rebuilding can disturb the tested shadow and always runs
	 * last. */
	int allow_intrusive;
};

struct poirot_timing_result {
	enum poirot_probe_status status;
	int error;
	uint64_t batch_ns;
	uint64_t alternating_ns;
	uint64_t control_batch_ns;
	uint64_t control_alternating_ns;
	uint64_t excess_per_iteration_ns;
	uint64_t call_excess_per_iteration_ns;
	uint32_t ratio_permille;
	uint32_t target_control_ratio_permille;
};

struct poirot_selfread_result {
	enum poirot_probe_status status;
	int error;
	uint64_t elapsed_ns;
	uint64_t value;
	int timed_out;
};

struct poirot_parallel_result {
	enum poirot_probe_status status;
	int error;
	uint64_t target_ns;
	uint64_t control_ns;
	uint64_t unexpected_results;
	uint32_t ratio_permille;
	int cpu_reader;
	int cpu_executor;
};

struct poirot_fork_result {
	enum poirot_probe_status status;
	int error;
	uint64_t expected;
	uint64_t parent_value;
	uint64_t child_value;
	int child_status;
	int timed_out;
};

struct poirot_protect_result {
	enum poirot_probe_status status;
	int error;
	int restore_error;
	uint64_t original_hash;
	uint64_t exposed_hash;
	size_t different_bytes;
	size_t first_difference;
	int original_prot;
};

struct poirot_shadow_report {
	uint32_t suspicious_checks;
	uint32_t suspicious_count;
	struct poirot_timing_result timing;
	struct poirot_selfread_result selfread_result;
	struct poirot_parallel_result parallel;
	struct poirot_fork_result fork_result;
	struct poirot_protect_result protect;
};

struct poirot_redirect_fault_result {
	enum poirot_probe_status status;
	int error;
	uintptr_t pc;
	uintptr_t lr;
	uintptr_t address;
	int pc_mapped;
	int pc_executable;
};

struct poirot_redirect_signal_result {
	enum poirot_probe_status status;
	int error;
	uint32_t requested;
	uint32_t delivered;
	uint32_t mapped_samples;
	uint32_t nonexec_samples;
	uint32_t unmapped_samples;
	uint32_t invalid_samples;
	uint32_t repeated_samples;
	uintptr_t first_unmapped_pc;
};

struct poirot_redirect_ghost_result {
	enum poirot_probe_status status;
	int error;
	uintptr_t address;
	int readable;
	int noreplace_errno;
	int child_status;
	int timed_out;
};

struct poirot_redirect_report {
	enum poirot_probe_status status;
	uint32_t checks;
	uint32_t suspicious_checks;
	uint32_t suspicious_count;
	struct poirot_redirect_fault_result fault;
	struct poirot_redirect_signal_result signal;
	struct poirot_redirect_ghost_result ghost;
};

struct poirot_hwpoint_result {
	enum poirot_probe_status status;
	int error;
	uint32_t advertised_slots;
	uint32_t opened_slots;
	uint32_t enabled_slots;
	uint32_t signaled_slots;
	uint32_t returned_slots;
	uint32_t counted_slots;
	uint32_t first_failed_slot;
};

struct poirot_report {
	enum poirot_verdict verdict;
	uint32_t detected_mechanisms;
	size_t page_size;
	uintptr_t target;
	uintptr_t target_page;
	uintptr_t control;
	uintptr_t activate;
	uintptr_t selfread;
	uintptr_t redirect_target;
	uintptr_t fault_target;
	struct poirot_shadow_report shadow;
	struct poirot_redirect_report redirect;
	struct poirot_hwpoint_result hwpoint;
};

void poirot_options_default(struct poirot_options *options);
int poirot_detect(const struct poirot_target *target,
		  const struct poirot_options *options,
		  struct poirot_report *report);
size_t poirot_report_format(const struct poirot_report *report, char *buffer,
			    size_t capacity);

const char *poirot_probe_status_name(enum poirot_probe_status status);
const char *poirot_verdict_name(enum poirot_verdict verdict);

#ifdef __cplusplus
}
#endif

#endif
