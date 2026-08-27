#include "signal.h"

#include "src/utils/memory.h"
#include "src/utils/signal.h"
#include "src/utils/time.h"

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>

#define REDIRECT_SAMPLE_CAPACITY 64u

struct signal_run {
	poirot_probe_fn function;
	atomic_uint ready;
	atomic_uint stop;
	atomic_uint count;
	atomic_int error;
	uintptr_t pcs[REDIRECT_SAMPLE_CAPACITY];
	unsigned char unmapped[REDIRECT_SAMPLE_CAPACITY];
};

static pthread_mutex_t signal_lock = PTHREAD_MUTEX_INITIALIZER;
static struct sigaction signal_previous;
static _Thread_local struct signal_run *signal_current;

static void signal_handler(int signal_number, siginfo_t *info,
			   void *raw_context) {
	struct signal_run *run = signal_current;
	uint32_t index;

	if (!run) {
		signal_forward(&signal_previous, signal_number, info, raw_context);
		return;
	}

	index = atomic_load_explicit(&run->count, memory_order_relaxed);
	if (index >= REDIRECT_SAMPLE_CAPACITY)
		return;
	run->pcs[index] = signal_pc(raw_context);
	atomic_store_explicit(&run->count, index + 1, memory_order_release);
}

static void *signal_worker(void *argument) {
	struct signal_run *run = argument;
	const int signal_number = SIGRTMIN + 7;
	sigset_t signals;
	sigset_t old_mask;
	uint64_t input = 0;
	int error;

	sigemptyset(&signals);
	sigaddset(&signals, signal_number);
	error = pthread_sigmask(SIG_UNBLOCK, &signals, &old_mask);
	if (error) {
		atomic_store_explicit(&run->error, error, memory_order_release);
		atomic_store_explicit(&run->ready, 1, memory_order_release);
		return NULL;
	}
	signal_current = run;
	atomic_store_explicit(&run->ready, 1, memory_order_release);
	while (!atomic_load_explicit(&run->stop, memory_order_acquire))
		input = run->function(input);
	signal_current = NULL;
	(void)pthread_sigmask(SIG_SETMASK, &old_mask, NULL);
	return NULL;
}

static void signal_classify(struct signal_run *run, size_t page_size,
			    struct poirot_redirect_signal_result *result) {
	uint32_t count = atomic_load_explicit(&run->count, memory_order_acquire);
	uint32_t i;

	for (i = 0; i < count; ++i) {
		struct poirot_memory_region region;
		uintptr_t pc = run->pcs[i];
		int error;

		if (!memory_user_address(pc)) {
			++result->invalid_samples;
			continue;
		}
		error = memory_query(pc, &region);
		if (!error) {
			++result->mapped_samples;
			if (!(region.prot & PROT_EXEC))
				++result->nonexec_samples;
			continue;
		}
		if (error != -ENOENT) {
			result->error = -error;
			continue;
		}

		++result->unmapped_samples;
		run->unmapped[i] = 1;
		if (!result->first_unmapped_pc)
			result->first_unmapped_pc = pc;
	}

	for (i = 0; i < count; ++i) {
		uintptr_t page;
		uint32_t repeated = 0;
		uint32_t j;

		if (!run->unmapped[i])
			continue;
		page = memory_page_start(run->pcs[i], page_size);
		for (j = 0; j < count; ++j) {
			if (run->unmapped[j] &&
			    memory_page_start(run->pcs[j], page_size) ==
				    page)
				++repeated;
		}
		if (repeated > result->repeated_samples)
			result->repeated_samples = repeated;
	}
}

int redirect_signal_probe(poirot_probe_fn function,
			  const struct poirot_options *options,
			  size_t page_size,
			  struct poirot_redirect_signal_result *result) {
#if defined(__aarch64__)
	const int signal_number = SIGRTMIN + 7;
	const struct timespec pause = {.tv_nsec = 50000};
	struct signal_run run = {
		.function = function,
		.ready = ATOMIC_VAR_INIT(0),
		.stop = ATOMIC_VAR_INIT(0),
		.count = ATOMIC_VAR_INIT(0),
		.error = ATOMIC_VAR_INIT(0),
	};
	struct sigaction action;
	pthread_t worker;
	uint64_t deadline;
	uint32_t requested;
	uint32_t i;
	int error;
	int thread_started = 0;

	if (!function || !options || !page_size || !result ||
	    options->redirect_samples < 4 || !options->redirect_timeout_ms ||
	    signal_number > SIGRTMAX)
		return -EINVAL;

	requested = options->redirect_samples;
	if (requested > REDIRECT_SAMPLE_CAPACITY)
		requested = REDIRECT_SAMPLE_CAPACITY;
	result->requested = requested;

	error = pthread_mutex_lock(&signal_lock);
	if (error)
		return -error;
	memset(&action, 0, sizeof(action));
	action.sa_sigaction = signal_handler;
	action.sa_flags = SA_SIGINFO;
	sigemptyset(&action.sa_mask);
	if (sigaction(signal_number, &action, &signal_previous) != 0) {
		error = -errno;
		goto unlock;
	}

	error = pthread_create(&worker, NULL, signal_worker, &run);
	if (error) {
		error = -error;
		goto restore_action;
	}
	thread_started = 1;
	while (!atomic_load_explicit(&run.ready, memory_order_acquire))
		sched_yield();
	error = atomic_load_explicit(&run.error, memory_order_acquire);
	if (error) {
		error = -error;
		goto sampled;
	}

	deadline = time_now_ns() +
		   (uint64_t)options->redirect_timeout_ms * UINT64_C(1000000);
	for (i = 0; i < requested; ++i) {
		uint32_t before =
			atomic_load_explicit(&run.count, memory_order_acquire);

		error = pthread_kill(worker, signal_number);
		if (error) {
			error = -error;
			break;
		}
		while (atomic_load_explicit(&run.count, memory_order_acquire) ==
		       before) {
			if (time_now_ns() >= deadline)
				goto sampled;
			(void)nanosleep(&pause, NULL);
		}
		(void)nanosleep(&pause, NULL);
	}

sampled:
	atomic_store_explicit(&run.stop, 1, memory_order_release);
	if (thread_started)
		(void)pthread_join(worker, NULL);
	result->delivered =
		atomic_load_explicit(&run.count, memory_order_acquire);
	signal_classify(&run, page_size, result);
	if (result->repeated_samples >= 2 || result->nonexec_samples)
		result->status = POIROT_PROBE_SUSPICIOUS;
	else if (result->error)
		result->status = POIROT_PROBE_ERROR;
	else if (result->unmapped_samples || result->invalid_samples ||
		 result->delivered < 4)
		result->status = POIROT_PROBE_INCONCLUSIVE;
	else
		result->status = POIROT_PROBE_CLEAN;
restore_action:
	if (sigaction(signal_number, &signal_previous, NULL) != 0 && !error)
		error = -errno;
unlock:
	(void)pthread_mutex_unlock(&signal_lock);
	return error;
#else
	(void)function;
	(void)options;
	(void)page_size;
	(void)result;
	return -ENOTSUP;
#endif
}
