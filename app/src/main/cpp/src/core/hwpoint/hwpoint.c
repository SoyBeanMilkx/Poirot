#define _GNU_SOURCE

#include "hwpoint.h"

#include "src/utils/signal.h"
#include "src/utils/time.h"

#include <errno.h>
#include <linux/elf.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define HWPOINT_CHILD_TIMEOUT_MS 1000u
#define HWPOINT_SIGNAL_BASE UINT64_C(0x504f495248570000)
#define HWPOINT_SIGNAL_MASK UINT64_C(0xffffffffffff0000)

typedef uint64_t (*hwpoint_probe_fn)(void);

#define HWPOINT_DECLARE(index) extern uint64_t hwpoint_probe_##index(void)
HWPOINT_DECLARE(0);
HWPOINT_DECLARE(1);
HWPOINT_DECLARE(2);
HWPOINT_DECLARE(3);
HWPOINT_DECLARE(4);
HWPOINT_DECLARE(5);
HWPOINT_DECLARE(6);
HWPOINT_DECLARE(7);
HWPOINT_DECLARE(8);
HWPOINT_DECLARE(9);
HWPOINT_DECLARE(10);
HWPOINT_DECLARE(11);
HWPOINT_DECLARE(12);
HWPOINT_DECLARE(13);
HWPOINT_DECLARE(14);
HWPOINT_DECLARE(15);
#undef HWPOINT_DECLARE

static const hwpoint_probe_fn hwpoint_probes[HWPOINT_SLOT_CAPACITY] = {
	hwpoint_probe_0,  hwpoint_probe_1,  hwpoint_probe_2,
	hwpoint_probe_3,  hwpoint_probe_4,  hwpoint_probe_5,
	hwpoint_probe_6,  hwpoint_probe_7,  hwpoint_probe_8,
	hwpoint_probe_9,  hwpoint_probe_10, hwpoint_probe_11,
	hwpoint_probe_12, hwpoint_probe_13, hwpoint_probe_14,
	hwpoint_probe_15,
};

struct hwpoint_run {
	uint32_t slots;
	uintptr_t sites[HWPOINT_SLOT_CAPACITY];
	volatile sig_atomic_t signals[HWPOINT_SLOT_CAPACITY];
	volatile sig_atomic_t handler_error;
};

struct hwpoint_read_value {
	uint64_t value;
	uint64_t time_enabled;
	uint64_t time_running;
};

struct hwpoint_resource_info {
	uint32_t info;
	uint32_t pad;
};

static pthread_mutex_t hwpoint_lock = PTHREAD_MUTEX_INITIALIZER;
static struct sigaction hwpoint_previous;
static _Thread_local struct hwpoint_run *hwpoint_current;

static uint32_t hwpoint_count_bits(uint32_t value) {
	uint32_t count = 0;

	while (value) {
		value &= value - 1u;
		++count;
	}
	return count;
}

static uint32_t hwpoint_expected_mask(uint32_t slots) {
	return slots >= 32 ? UINT32_MAX : (UINT32_C(1) << slots) - 1u;
}

static uint64_t hwpoint_random(uint64_t *state) {
	uint64_t value = *state;

	value ^= value << 13;
	value ^= value >> 7;
	value ^= value << 17;
	*state = value;
	return value;
}

static void hwpoint_shuffle(uint32_t *order, uint32_t count,
			    uint64_t *state) {
	uint32_t i;

	for (i = count; i > 1; --i) {
		uint32_t index = (uint32_t)(hwpoint_random(state) % i);
		uint32_t value = order[i - 1];

		order[i - 1] = order[index];
		order[index] = value;
	}
}

static int hwpoint_wait(pid_t child, int *status, uint32_t timeout_ms) {
	const struct timespec pause = {.tv_nsec = 1000000};
	uint64_t deadline;

	deadline = time_now_ns() +
		   (uint64_t)timeout_ms * UINT64_C(1000000);
	for (;;) {
		pid_t waited = waitpid(child, status, WNOHANG | WUNTRACED);

		if (waited == child)
			return 0;
		if (waited < 0 && errno != EINTR)
			return -errno;
		if (time_now_ns() >= deadline)
			return -ETIMEDOUT;
		(void)nanosleep(&pause, NULL);
	}
}

static void hwpoint_reap(pid_t child) {
	int status;

	(void)kill(child, SIGKILL);
	while (waitpid(child, &status, 0) < 0 && errno == EINTR)
		;
}

static int hwpoint_query_slots(uint32_t *slots) {
#if defined(__aarch64__)
	struct hwpoint_resource_info resource = {0};
	struct iovec vector = {
		.iov_base = &resource,
		.iov_len = sizeof(resource),
	};
	pid_t child;
	int status;
	int error;

	if (!slots)
		return -EINVAL;

	child = fork();
	if (child < 0)
		return -errno;
	if (!child) {
		int child_error;

		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0) {
			child_error = errno;
			_exit(child_error > 0 && child_error < 126
				      ? child_error
				      : 127);
		}
		(void)syscall(SYS_tgkill, getpid(), syscall(SYS_gettid),
			      SIGSTOP);
		_exit(0);
	}

	error = hwpoint_wait(child, &status, HWPOINT_CHILD_TIMEOUT_MS);
	if (error) {
		hwpoint_reap(child);
		return error;
	}
	if (!WIFSTOPPED(status)) {
		if (WIFEXITED(status) && WEXITSTATUS(status))
			return -WEXITSTATUS(status);
		return -EIO;
	}

	if (ptrace(PTRACE_GETREGSET, child,
		   (void *)(uintptr_t)NT_ARM_HW_BREAK, &vector) != 0) {
		error = -errno;
		hwpoint_reap(child);
		return error;
	}
	if (ptrace(PTRACE_DETACH, child, NULL, NULL) != 0) {
		error = -errno;
		hwpoint_reap(child);
		return error;
	}

	error = hwpoint_wait(child, &status, HWPOINT_CHILD_TIMEOUT_MS);
	if (error) {
		hwpoint_reap(child);
		return error;
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status))
		return -EIO;

	*slots = resource.info & UINT32_C(0xff);
	if (!*slots || *slots > HWPOINT_SLOT_CAPACITY)
		return -ERANGE;
	return 0;
#else
	(void)slots;
	return -ENOTSUP;
#endif
}

static void hwpoint_signal_handler(int signal_number, siginfo_t *info,
				   void *raw_context) {
	struct hwpoint_run *run = hwpoint_current;
	uint64_t data;
	uint32_t index;
	uintptr_t pc;

	if (!run || !info || info->si_code != TRAP_PERF) {
		signal_forward(&hwpoint_previous, signal_number, info, raw_context);
		return;
	}

	data = (uint64_t)(unsigned long)info->si_perf_data;
	if ((data & HWPOINT_SIGNAL_MASK) != HWPOINT_SIGNAL_BASE) {
		signal_forward(&hwpoint_previous, signal_number, info, raw_context);
		return;
	}
	index = (uint32_t)(data & UINT64_C(0xffff));
	if (!index || index > run->slots) {
		signal_forward(&hwpoint_previous, signal_number, info, raw_context);
		return;
	}
	--index;
	pc = signal_pc(raw_context);
	if (pc != run->sites[index] && pc != run->sites[index] + 4) {
		run->handler_error = EPROTO;
		return;
	}
	if (signal_set_register(raw_context, 0, 1) != 0) {
		run->handler_error = EINVAL;
		return;
	}
	if (pc == run->sites[index] &&
	    signal_set_pc(raw_context, pc + 4) != 0) {
		run->handler_error = EINVAL;
		return;
	}
	++run->signals[index];
}

static int hwpoint_open(uintptr_t address, uint32_t index) {
#if defined(__aarch64__)
	struct perf_event_attr attribute;

	memset(&attribute, 0, sizeof(attribute));
	attribute.type = PERF_TYPE_BREAKPOINT;
	attribute.size = sizeof(attribute);
	attribute.sample_period = 1;
	attribute.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_ADDR;
	attribute.read_format = PERF_FORMAT_TOTAL_TIME_ENABLED |
				PERF_FORMAT_TOTAL_TIME_RUNNING;
	attribute.disabled = 1;
	attribute.pinned = 1;
	attribute.exclude_kernel = 1;
	attribute.exclude_hv = 1;
	attribute.remove_on_exec = 1;
	attribute.sigtrap = 1;
	attribute.bp_type = HW_BREAKPOINT_X;
	attribute.bp_addr = address;
	attribute.bp_len = HW_BREAKPOINT_LEN_4;
	attribute.sig_data = HWPOINT_SIGNAL_BASE | (uint64_t)(index + 1u);
	return (int)syscall(SYS_perf_event_open, &attribute, 0, -1, -1,
			    PERF_FLAG_FD_CLOEXEC);
#else
	(void)address;
	(void)index;
	errno = ENOTSUP;
	return -1;
#endif
}

static int hwpoint_read(int descriptor, struct hwpoint_read_value *value) {
	ssize_t size;

	do {
		size = read(descriptor, value, sizeof(*value));
	} while (size < 0 && errno == EINTR);
	if (size < 0)
		return -errno;
	return size == (ssize_t)sizeof(*value) ? 0 : -EIO;
}

static int hwpoint_unavailable(int error) {
	return error == EACCES || error == EPERM || error == ENOSYS ||
	       error == EOPNOTSUPP || error == EINVAL;
}

int hwpoint_detect(const struct poirot_options *options,
		   struct poirot_report *report) {
	struct poirot_hwpoint_result *result;
	struct hwpoint_run run;
	struct sigaction action;
	sigset_t trap_set;
	sigset_t old_mask;
	uint32_t returned = 0;
	uint32_t return_failed = 0;
	uint32_t signaled = 0;
	uint32_t counted = 0;
	uint32_t order[HWPOINT_SLOT_CAPACITY];
	uint32_t expected;
	uint64_t random_state;
	int descriptors[HWPOINT_SLOT_CAPACITY];
	int action_installed = 0;
	int mask_saved = 0;
	int locked = 0;
	int error;
	uint32_t i;

	if (!options || !report)
		return -EINVAL;
	result = &report->hwpoint;
	result->status = POIROT_PROBE_SKIPPED;
	result->first_failed_slot = UINT32_MAX;
	if (!(options->checks & POIROT_CHECK_HWPOINT))
		return 0;

	error = hwpoint_query_slots(&result->advertised_slots);
	if (error) {
		result->status = POIROT_PROBE_INCONCLUSIVE;
		result->error = -error;
		return 0;
	}

	memset(&run, 0, sizeof(run));
	run.slots = result->advertised_slots;
	for (i = 0; i < HWPOINT_SLOT_CAPACITY; ++i)
		descriptors[i] = -1;
	for (i = 0; i < run.slots; ++i)
		run.sites[i] = (uintptr_t)hwpoint_probes[i] + 4;
	for (i = 0; i < run.slots; ++i)
		order[i] = i;
	random_state = time_now_ns() ^ (uintptr_t)&run ^
		       (uint64_t)syscall(SYS_gettid);
	if (!random_state)
		random_state = HWPOINT_SIGNAL_BASE;

	error = pthread_mutex_lock(&hwpoint_lock);
	if (error) {
		result->status = POIROT_PROBE_ERROR;
		result->error = error;
		return 0;
	}
	locked = 1;

	memset(&action, 0, sizeof(action));
	action.sa_sigaction = hwpoint_signal_handler;
	action.sa_flags = SA_SIGINFO;
	sigemptyset(&action.sa_mask);
	if (sigaction(SIGTRAP, &action, &hwpoint_previous) != 0) {
		result->status = POIROT_PROBE_ERROR;
		result->error = errno;
		goto cleanup;
	}
	action_installed = 1;

	sigemptyset(&trap_set);
	sigaddset(&trap_set, SIGTRAP);
	error = pthread_sigmask(SIG_UNBLOCK, &trap_set, &old_mask);
	if (error) {
		result->status = POIROT_PROBE_ERROR;
		result->error = error;
		goto cleanup;
	}
	mask_saved = 1;
	hwpoint_current = &run;

	for (i = 0; i < run.slots; ++i) {
		descriptors[i] = hwpoint_open(run.sites[i], i);
		if (descriptors[i] < 0) {
			result->error = errno;
			result->first_failed_slot = i;
			break;
		}
		++result->opened_slots;
	}
	if (result->opened_slots != run.slots) {
		result->status = !result->opened_slots &&
					 hwpoint_unavailable(result->error)
				 ? POIROT_PROBE_INCONCLUSIVE
				 : POIROT_PROBE_SUSPICIOUS;
		goto cleanup;
	}

	for (i = 0; i < run.slots; ++i) {
		if (ioctl(descriptors[i], PERF_EVENT_IOC_ENABLE, 0) != 0) {
			result->error = errno;
			result->first_failed_slot = i;
			result->status = POIROT_PROBE_SUSPICIOUS;
			goto cleanup;
		}
		++result->enabled_slots;
	}

	for (i = 0; i < HWPOINT_PROBE_ROUNDS; ++i) {
		uint32_t step;

		hwpoint_shuffle(order, run.slots, &random_state);
		for (step = 0; step < run.slots; ++step) {
			uint32_t index = order[step];
			uint64_t value = hwpoint_probes[index]();

			if (value == 1)
				returned |= UINT32_C(1) << index;
			else
				return_failed |= UINT32_C(1) << index;
		}
	}
	for (i = 0; i < run.slots; ++i) {
		struct hwpoint_read_value value = {0};

		if (hwpoint_read(descriptors[i], &value) != 0) {
			if (!result->error)
				result->error = EIO;
			continue;
		}
		if (value.value >= HWPOINT_PROBE_ROUNDS && value.time_enabled &&
		    value.time_running)
			counted |= UINT32_C(1) << i;
		if ((uint32_t)run.signals[i] >= HWPOINT_PROBE_ROUNDS)
			signaled |= UINT32_C(1) << i;
	}

	expected = hwpoint_expected_mask(run.slots);
	returned &= ~return_failed;
	result->signaled_slots = hwpoint_count_bits(signaled & expected);
	result->returned_slots = hwpoint_count_bits(returned & expected);
	result->counted_slots = hwpoint_count_bits(counted & expected);
	if (run.handler_error) {
		result->error = run.handler_error;
		result->status = POIROT_PROBE_SUSPICIOUS;
	} else if ((signaled & returned & counted & expected) == expected) {
		result->status = POIROT_PROBE_CLEAN;
	} else {
		result->status = POIROT_PROBE_SUSPICIOUS;
	}

cleanup:
	for (i = 0; i < HWPOINT_SLOT_CAPACITY; ++i) {
		if (descriptors[i] < 0)
			continue;
		(void)ioctl(descriptors[i], PERF_EVENT_IOC_DISABLE, 0);
		close(descriptors[i]);
	}
	hwpoint_current = NULL;
	if (mask_saved)
		(void)pthread_sigmask(SIG_SETMASK, &old_mask, NULL);
	if (action_installed)
		(void)sigaction(SIGTRAP, &hwpoint_previous, NULL);
	if (locked)
		(void)pthread_mutex_unlock(&hwpoint_lock);
	return 0;
}
