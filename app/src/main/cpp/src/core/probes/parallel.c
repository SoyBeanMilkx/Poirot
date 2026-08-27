#include "src/core/probes/parallel.h"

#include "src/utils/thread.h"
#include "src/utils/time.h"

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>

struct parallel_run {
	poirot_probe_fn function;
	poirot_expected_fn expected;
	void *expected_context;
	volatile const uint32_t *instruction;
	uint32_t iterations;
	int reader_cpu;
	int executor_cpu;
	atomic_uint ready;
	atomic_uint start;
	atomic_ullong unexpected;
};

static volatile uint64_t parallel_sink;

static uint32_t parallel_ratio(uint64_t numerator, uint64_t denominator) {
	__uint128_t scaled;

	if (!denominator)
		return UINT32_MAX;
	scaled = (__uint128_t)numerator * 1000u / denominator;
	return scaled > UINT32_MAX ? UINT32_MAX : (uint32_t)scaled;
}

static void parallel_wait_start(struct parallel_run *run) {
	atomic_fetch_add_explicit(&run->ready, 1, memory_order_release);
	while (!atomic_load_explicit(&run->start, memory_order_acquire))
		sched_yield();
}

static void *parallel_reader(void *argument) {
	struct parallel_run *run = argument;
	uint64_t accumulator = 0;
	uint32_t i;

	if (run->reader_cpu >= 0)
		(void)poirot_thread_pin(run->reader_cpu);
	parallel_wait_start(run);
	for (i = 0; i < run->iterations; ++i)
		accumulator += *run->instruction;
	parallel_sink = accumulator;
	return NULL;
}

static void *parallel_executor(void *argument) {
	struct parallel_run *run = argument;
	uint64_t unexpected = 0;
	uint32_t i;

	if (run->executor_cpu >= 0)
		(void)poirot_thread_pin(run->executor_cpu);
	parallel_wait_start(run);
	for (i = 0; i < run->iterations; ++i) {
		uint64_t input = (uint64_t)i * UINT64_C(0x9e3779b1);
		uint64_t actual = run->function(input);

		if (actual != run->expected(input, run->expected_context))
			++unexpected;
	}
	atomic_store_explicit(&run->unexpected, unexpected,
			      memory_order_release);
	return NULL;
}

static int parallel_measure(poirot_probe_fn function,
			    const struct poirot_target *target,
			    uint32_t iterations, int reader_cpu,
			    int executor_cpu, uint64_t *elapsed,
			    uint64_t *unexpected) {
	struct parallel_run run = {
		.function = function,
		.expected = target->expected,
		.expected_context = target->expected_context,
		.instruction = (volatile const uint32_t *)(uintptr_t)function,
		.iterations = iterations,
		.reader_cpu = reader_cpu,
		.executor_cpu = executor_cpu,
		.ready = ATOMIC_VAR_INIT(0),
		.start = ATOMIC_VAR_INIT(0),
		.unexpected = ATOMIC_VAR_INIT(0),
	};
	pthread_t reader;
	pthread_t executor;
	uint64_t started;
	int error;

	error = pthread_create(&reader, NULL, parallel_reader, &run);
	if (error)
		return -error;
	error = pthread_create(&executor, NULL, parallel_executor, &run);
	if (error) {
		atomic_store_explicit(&run.start, 1, memory_order_release);
		(void)pthread_join(reader, NULL);
		return -error;
	}

	while (atomic_load_explicit(&run.ready, memory_order_acquire) != 2)
		sched_yield();
	started = poirot_time_now_ns();
	atomic_store_explicit(&run.start, 1, memory_order_release);
	(void)pthread_join(reader, NULL);
	(void)pthread_join(executor, NULL);
	*elapsed = poirot_time_now_ns() - started;
	*unexpected =
		atomic_load_explicit(&run.unexpected, memory_order_acquire);
	return 0;
}

int poirot_parallel_probe(const struct poirot_target *target,
			  const struct poirot_options *options,
			  struct poirot_parallel_result *result) {
	uint64_t target_samples[3];
	uint64_t control_samples[3];
	uint64_t control_unexpected = 0;
	uint64_t excess;
	uint32_t round;
	uint32_t iterations;
	int reader_cpu;
	int executor_cpu;
	int error;

	if (!target || !target->target || !target->control ||
	    !target->expected || !options || !result ||
	    !options->parallel_iterations)
		return -EINVAL;

	result->cpu_reader = -1;
	result->cpu_executor = -1;
	(void)poirot_thread_choose_cpus(&result->cpu_reader,
					&result->cpu_executor);
	iterations = options->parallel_iterations;
	reader_cpu = result->cpu_reader;
	executor_cpu = result->cpu_executor;

	for (round = 0; round < 3; ++round) {
		uint64_t target_unexpected = 0;
		uint64_t round_control_unexpected = 0;

		if (!(round & 1)) {
			error = parallel_measure(
				target->control, target, iterations, reader_cpu,
				executor_cpu, &control_samples[round],
				&round_control_unexpected);
			if (!error)
				error = parallel_measure(target->target, target,
							 iterations, reader_cpu,
							 executor_cpu,
							 &target_samples[round],
							 &target_unexpected);
		} else {
			error = parallel_measure(
				target->target, target, iterations, reader_cpu,
				executor_cpu, &target_samples[round],
				&target_unexpected);
			if (!error)
				error = parallel_measure(
					target->control, target, iterations,
					reader_cpu, executor_cpu,
					&control_samples[round],
					&round_control_unexpected);
		}
		if (error)
			return error;
		result->unexpected_results += target_unexpected;
		control_unexpected += round_control_unexpected;
	}

	result->target_ns = poirot_time_median(target_samples, 3);
	result->control_ns = poirot_time_median(control_samples, 3);
	result->unexpected_results += control_unexpected;
	result->ratio_permille =
		parallel_ratio(result->target_ns, result->control_ns);
	excess = result->target_ns > result->control_ns
			 ? (result->target_ns - result->control_ns) / iterations
			 : 0;
	if (result->unexpected_results ||
	    (result->ratio_permille >= options->parallel_ratio_permille &&
	     excess >= options->parallel_min_excess_ns))
		result->status = POIROT_PROBE_SUSPICIOUS;
	else if (result->cpu_reader < 0 ||
		 result->cpu_reader == result->cpu_executor)
		result->status = POIROT_PROBE_INCONCLUSIVE;
	else
		result->status = POIROT_PROBE_CLEAN;
	return 0;
}
