#include "fault.h"

#include "src/utils/memory.h"
#include "src/utils/signal.h"

#include <errno.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>

struct fault_context {
	sigjmp_buf environment;
	volatile sig_atomic_t armed;
	uintptr_t pc;
	uintptr_t lr;
	uintptr_t address;
};

static pthread_mutex_t fault_lock = PTHREAD_MUTEX_INITIALIZER;
static struct sigaction fault_previous;
static _Thread_local struct fault_context fault_current;

static void fault_handler(int signal_number, siginfo_t *info,
			  void *raw_context) {
	if (!fault_current.armed) {
		signal_forward(&fault_previous, signal_number, info, raw_context);
		return;
	}

	fault_current.pc = signal_pc(raw_context);
	fault_current.lr = signal_lr(raw_context);
	fault_current.address = (uintptr_t)info->si_addr;
	fault_current.armed = 0;
	siglongjmp(fault_current.environment, 1);
}

int redirect_fault_probe(poirot_probe_fn function,
			 struct poirot_redirect_fault_result *result) {
#if defined(__aarch64__)
	struct poirot_memory_region region;
	struct sigaction action;
	sigset_t signals;
	sigset_t old_mask;
	int error;
	int restored;
	int returned = 0;

	if (!function || !result)
		return -EINVAL;

	error = pthread_mutex_lock(&fault_lock);
	if (error)
		return -error;

	memset(&fault_current, 0, sizeof(fault_current));
	memset(&action, 0, sizeof(action));
	action.sa_sigaction = fault_handler;
	action.sa_flags = SA_SIGINFO;
	sigemptyset(&action.sa_mask);
	if (sigaction(SIGSEGV, &action, &fault_previous) != 0) {
		error = -errno;
		goto unlock;
	}

	sigemptyset(&signals);
	sigaddset(&signals, SIGSEGV);
	error = pthread_sigmask(SIG_UNBLOCK, &signals, &old_mask);
	if (error) {
		error = -error;
		goto restore_action;
	}

	if (sigsetjmp(fault_current.environment, 1) == 0) {
		fault_current.armed = 1;
		(void)function(0);
		fault_current.armed = 0;
		returned = 1;
	}

	result->pc = fault_current.pc;
	result->lr = fault_current.lr;
	result->address = fault_current.address;
	if (returned || !memory_user_address(result->pc)) {
		result->status = POIROT_PROBE_INCONCLUSIVE;
	} else {
		error = memory_query(result->pc, &region);
		if (!error) {
			result->pc_mapped = 1;
			result->pc_executable = !!(region.prot & PROT_EXEC);
			result->status = result->pc_executable
					 ? POIROT_PROBE_CLEAN
					 : POIROT_PROBE_SUSPICIOUS;
		} else if (error == -ENOENT) {
			result->status = POIROT_PROBE_SUSPICIOUS;
			error = 0;
		} else {
			result->status = POIROT_PROBE_ERROR;
			result->error = -error;
		}
	}

	restored = pthread_sigmask(SIG_SETMASK, &old_mask, NULL);
	if (restored && !error)
		error = -restored;
restore_action:
	restored = sigaction(SIGSEGV, &fault_previous, NULL);
	if (restored && !error)
		error = -errno;
unlock:
	(void)pthread_mutex_unlock(&fault_lock);
	return error;
#else
	(void)function;
	(void)result;
	return -ENOTSUP;
#endif
}
