#include "poirot.h"

#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>

struct report_writer {
	char *buffer;
	size_t capacity;
	size_t length;
};

static void report_append(struct report_writer *writer, const char *format,
			  ...) {
	va_list arguments;
	int written;

	if (!writer->capacity || writer->length >= writer->capacity)
		return;
	va_start(arguments, format);
	written =
		vsnprintf(writer->buffer + writer->length,
			  writer->capacity - writer->length, format, arguments);
	va_end(arguments);
	if (written < 0)
		return;
	if ((size_t)written >= writer->capacity - writer->length)
		writer->length = writer->capacity - 1;
	else
		writer->length += (size_t)written;
}

const char *poirot_probe_status_name(enum poirot_probe_status status) {
	switch (status) {
	case POIROT_PROBE_SKIPPED:
		return "skipped";
	case POIROT_PROBE_CLEAN:
		return "clean";
	case POIROT_PROBE_SUSPICIOUS:
		return "suspicious";
	case POIROT_PROBE_INCONCLUSIVE:
		return "inconclusive";
	case POIROT_PROBE_ERROR:
		return "error";
	default:
		return "unknown";
	}
}

const char *poirot_verdict_name(enum poirot_verdict verdict) {
	switch (verdict) {
	case POIROT_VERDICT_CLEAN:
		return "clean";
	case POIROT_VERDICT_ANOMALOUS:
		return "anomalous";
	case POIROT_VERDICT_DETECTED:
		return "detected";
	case POIROT_VERDICT_INCONCLUSIVE:
		return "inconclusive";
	default:
		return "unknown";
	}
}

size_t poirot_report_format(const struct poirot_report *report, char *buffer,
			    size_t capacity) {
	struct report_writer writer = {
		.buffer = buffer,
		.capacity = capacity,
	};
	const char *first_difference;
	char first_buffer[32];

	if (!report || !buffer || !capacity)
		return 0;
	buffer[0] = '\0';
	if (report->protect.first_difference == SIZE_MAX)
		first_difference = "none";
	else {
		(void)snprintf(first_buffer, sizeof(first_buffer), "0x%zx",
			       report->protect.first_difference);
		first_difference = first_buffer;
	}

	report_append(&writer,
		      "Poirot wxshadow probes\n"
		      "verdict: %s   hits: %u/5   mask: 0x%02" PRIx32 "\n\n"
		      "fixture\n"
		      "  page size : %zu\n"
		      "  target    : 0x%" PRIxPTR "\n"
		      "  page      : 0x%" PRIxPTR "\n"
		      "  activate  : 0x%" PRIxPTR "\n"
		      "  self-read : 0x%" PRIxPTR "\n"
		      "  control   : 0x%" PRIxPTR "\n\n",
		      poirot_verdict_name(report->verdict),
		      report->suspicious_count, report->suspicious_checks,
		      report->page_size, report->target, report->target_page,
		      report->activate, report->selfread, report->control);

	report_append(&writer,
		      "1. alternating read/execute: %s (errno=%d)\n"
		      "   target  batch=%" PRIu64 " ns  alternating=%" PRIu64
		      " ns  ratio=%u.%03ux\n"
		      "   control batch=%" PRIu64 " ns  alternating=%" PRIu64
		      " ns\n"
		      "   switch excess=%" PRIu64 " ns/iteration\n"
		      "   target/control=%u.%03ux  call excess=%" PRIu64
		      " ns/iteration\n\n",
		      poirot_probe_status_name(report->timing.status),
		      report->timing.error, report->timing.batch_ns,
		      report->timing.alternating_ns,
		      report->timing.ratio_permille / 1000,
		      report->timing.ratio_permille % 1000,
		      report->timing.control_batch_ns,
		      report->timing.control_alternating_ns,
		      report->timing.excess_per_iteration_ns,
		      report->timing.target_control_ratio_permille / 1000,
		      report->timing.target_control_ratio_permille % 1000,
		      report->timing.call_excess_per_iteration_ns);

	report_append(&writer,
		      "2. same-page self-read: %s (errno=%d)\n"
		      "   timeout=%s  elapsed=%" PRIu64 " ns\n"
		      "   value=0x%016" PRIx64 "\n\n",
		      poirot_probe_status_name(report->selfread_result.status),
		      report->selfread_result.error,
		      report->selfread_result.timed_out ? "yes" : "no",
		      report->selfread_result.elapsed_ns,
		      report->selfread_result.value);

	report_append(&writer,
		      "3. permission rebuild: %s (errno=%d, restore=%d)\n"
		      "   clean hash  =0x%016" PRIx64 "\n"
		      "   exposed hash=0x%016" PRIx64 "\n"
		      "   changed=%zu  first=%s  original prot=%c%c%c\n\n",
		      poirot_probe_status_name(report->protect.status),
		      report->protect.error, report->protect.restore_error,
		      report->protect.original_hash,
		      report->protect.exposed_hash,
		      report->protect.different_bytes, first_difference,
		      report->protect.original_prot & 1 ? 'r' : '-',
		      report->protect.original_prot & 2 ? 'w' : '-',
		      report->protect.original_prot & 4 ? 'x' : '-');

	report_append(&writer,
		      "4. parallel read/execute: %s (errno=%d)\n"
		      "   target=%" PRIu64 " ns  control=%" PRIu64
		      " ns  ratio=%u.%03ux\n"
		      "   unexpected=%" PRIu64 "  cpus=%d/%d\n\n",
		      poirot_probe_status_name(report->parallel.status),
		      report->parallel.error, report->parallel.target_ns,
		      report->parallel.control_ns,
		      report->parallel.ratio_permille / 1000,
		      report->parallel.ratio_permille % 1000,
		      report->parallel.unexpected_results,
		      report->parallel.cpu_reader,
		      report->parallel.cpu_executor);

	report_append(&writer,
		      "5. fork behavior: %s (errno=%d)\n"
		      "   expected=0x%016" PRIx64 "\n"
		      "   parent  =0x%016" PRIx64 "\n"
		      "   child   =0x%016" PRIx64 "\n"
		      "   wait status=0x%x  timeout=%s\n\n"
		      "Note: probe 3 is intrusive but executes last. If it "
		      "detects a\n"
		      "shadow, restart the process before testing that page "
		      "again. A clean\n"
		      "result means no evidence was found; it is not proof of "
		      "absence.",
		      poirot_probe_status_name(report->fork_result.status),
		      report->fork_result.error, report->fork_result.expected,
		      report->fork_result.parent_value,
		      report->fork_result.child_value,
		      report->fork_result.child_status,
		      report->fork_result.timed_out ? "yes" : "no");
	return writer.length;
}
