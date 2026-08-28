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
	const char *first_failed_slot;
	char first_buffer[32];
	char slot_buffer[32];

	if (!report || !buffer || !capacity)
		return 0;
	buffer[0] = '\0';
	if (report->shadow.protect.first_difference == SIZE_MAX)
		first_difference = "none";
	else {
		(void)snprintf(first_buffer, sizeof(first_buffer), "0x%zx",
			       report->shadow.protect.first_difference);
		first_difference = first_buffer;
	}
	if (report->hwpoint.first_failed_slot == UINT32_MAX)
		first_failed_slot = "none";
	else {
		(void)snprintf(slot_buffer, sizeof(slot_buffer), "%u",
			       report->hwpoint.first_failed_slot);
		first_failed_slot = slot_buffer;
	}

	report_append(&writer,
		      "Poirot hook detection\n"
		      "verdict: %s   mechanisms: 0x%02" PRIx32 "\n\n"
		      "target\n"
		      "  page size : %zu\n"
		      "  target    : 0x%" PRIxPTR "\n"
		      "  page      : 0x%" PRIxPTR "\n"
		      "  activate  : 0x%" PRIxPTR "\n"
		      "  self-read : 0x%" PRIxPTR "\n"
		      "  redirect  : 0x%" PRIxPTR "\n"
		      "  fault     : 0x%" PRIxPTR "\n"
		      "  control   : 0x%" PRIxPTR "\n\n",
		      poirot_verdict_name(report->verdict),
		      report->detected_mechanisms,
		      report->page_size, report->target, report->target_page,
		      report->activate, report->selfread,
		      report->redirect_target, report->fault_target,
		      report->control);
	report_append(&writer,
		      "shadow / same-VA PFN switching\n"
		      "hits: %u/5   mask: 0x%02" PRIx32 "\n\n",
		      report->shadow.suspicious_count,
		      report->shadow.suspicious_checks);

	report_append(&writer,
		      "1. alternating read/execute: %s (errno=%d)\n"
		      "   target  batch=%" PRIu64 " ns  alternating=%" PRIu64
		      " ns  ratio=%u.%03ux\n"
		      "   control batch=%" PRIu64 " ns  alternating=%" PRIu64
		      " ns\n"
		      "   switch excess=%" PRIu64 " ns/iteration\n"
		      "   target/control=%u.%03ux  call excess=%" PRIu64
		      " ns/iteration\n\n",
		      poirot_probe_status_name(report->shadow.timing.status),
		      report->shadow.timing.error,
		      report->shadow.timing.batch_ns,
		      report->shadow.timing.alternating_ns,
		      report->shadow.timing.ratio_permille / 1000,
		      report->shadow.timing.ratio_permille % 1000,
		      report->shadow.timing.control_batch_ns,
		      report->shadow.timing.control_alternating_ns,
		      report->shadow.timing.excess_per_iteration_ns,
		      report->shadow.timing.target_control_ratio_permille / 1000,
		      report->shadow.timing.target_control_ratio_permille % 1000,
		      report->shadow.timing.call_excess_per_iteration_ns);

	report_append(&writer,
		      "2. same-page self-read: %s (errno=%d)\n"
		      "   timeout=%s  elapsed=%" PRIu64 " ns\n"
		      "   value=0x%016" PRIx64 "\n\n",
		      poirot_probe_status_name(
			      report->shadow.selfread_result.status),
		      report->shadow.selfread_result.error,
		      report->shadow.selfread_result.timed_out ? "yes" : "no",
		      report->shadow.selfread_result.elapsed_ns,
		      report->shadow.selfread_result.value);

	report_append(&writer,
		      "3. permission rebuild: %s (errno=%d, restore=%d)\n"
		      "   clean hash  =0x%016" PRIx64 "\n"
		      "   exposed hash=0x%016" PRIx64 "\n"
		      "   changed=%zu  first=%s  original prot=%c%c%c\n\n",
		      poirot_probe_status_name(report->shadow.protect.status),
		      report->shadow.protect.error,
		      report->shadow.protect.restore_error,
		      report->shadow.protect.original_hash,
		      report->shadow.protect.exposed_hash,
		      report->shadow.protect.different_bytes, first_difference,
		      report->shadow.protect.original_prot & 1 ? 'r' : '-',
		      report->shadow.protect.original_prot & 2 ? 'w' : '-',
		      report->shadow.protect.original_prot & 4 ? 'x' : '-');

	report_append(&writer,
		      "4. parallel read/execute: %s (errno=%d)\n"
		      "   target=%" PRIu64 " ns  control=%" PRIu64
		      " ns  ratio=%u.%03ux\n"
		      "   unexpected=%" PRIu64 "  cpus=%d/%d\n\n",
		      poirot_probe_status_name(report->shadow.parallel.status),
		      report->shadow.parallel.error,
		      report->shadow.parallel.target_ns,
		      report->shadow.parallel.control_ns,
		      report->shadow.parallel.ratio_permille / 1000,
		      report->shadow.parallel.ratio_permille % 1000,
		      report->shadow.parallel.unexpected_results,
		      report->shadow.parallel.cpu_reader,
		      report->shadow.parallel.cpu_executor);

	report_append(&writer,
		      "5. fork behavior: %s (errno=%d)\n"
		      "   expected=0x%016" PRIx64 "\n"
		      "   parent  =0x%016" PRIx64 "\n"
		      "   child   =0x%016" PRIx64 "\n"
		      "   wait status=0x%x  timeout=%s\n\n",
		      poirot_probe_status_name(report->shadow.fork_result.status),
		      report->shadow.fork_result.error,
		      report->shadow.fork_result.expected,
		      report->shadow.fork_result.parent_value,
		      report->shadow.fork_result.child_value,
		      report->shadow.fork_result.child_status,
		      report->shadow.fork_result.timed_out ? "yes" : "no");

	report_append(&writer,
		      "redirect / cross-VA execution\n"
		      "status: %s   hits: %u/3   mask: 0x%03" PRIx32
		      "\n\n"
		      "6. controlled data fault: %s (errno=%d)\n"
		      "   pc=0x%" PRIxPTR "  lr=0x%" PRIxPTR "\n"
		      "   address=0x%" PRIxPTR "  mapped=%s  executable=%s\n\n"
		      "7. asynchronous PC sample: %s (errno=%d)\n"
		      "   delivered=%u/%u  mapped=%u  nonexec=%u\n"
		      "   unmapped=%u  invalid=%u\n"
		      "   repeated=%u  first=0x%" PRIxPTR "\n\n"
		      "8. ghost page: %s (errno=%d)\n"
		      "   address=0x%" PRIxPTR "  readable=%s\n"
		      "   MAP_FIXED_NOREPLACE errno=%d\n"
		      "   wait status=0x%x  timeout=%s\n\n",
		      poirot_probe_status_name(report->redirect.status),
		      report->redirect.suspicious_count,
		      report->redirect.suspicious_checks,
		      poirot_probe_status_name(report->redirect.fault.status),
		      report->redirect.fault.error, report->redirect.fault.pc,
		      report->redirect.fault.lr,
		      report->redirect.fault.address,
		      report->redirect.fault.pc_mapped ? "yes" : "no",
		      report->redirect.fault.pc_executable ? "yes" : "no",
		      poirot_probe_status_name(report->redirect.signal.status),
		      report->redirect.signal.error,
		      report->redirect.signal.delivered,
		      report->redirect.signal.requested,
		      report->redirect.signal.mapped_samples,
		      report->redirect.signal.nonexec_samples,
		      report->redirect.signal.unmapped_samples,
		      report->redirect.signal.invalid_samples,
		      report->redirect.signal.repeated_samples,
		      report->redirect.signal.first_unmapped_pc,
		      poirot_probe_status_name(report->redirect.ghost.status),
		      report->redirect.ghost.error,
		      report->redirect.ghost.address,
		      report->redirect.ghost.readable ? "yes" : "no",
		      report->redirect.ghost.noreplace_errno,
		      report->redirect.ghost.child_status,
		      report->redirect.ghost.timed_out ? "yes" : "no");

	report_append(&writer,
		      "hardware breakpoints\n"
		      "9. capacity and delivery: %s (errno=%d)\n"
		      "   advertised=%u  opened=%u  enabled=%u\n"
		      "   signaled=%u  returned=%u  counted=%u\n"
		      "   first failed slot=%s\n\n"
		      "Note: probe 3 is intrusive and executes last. A clean "
		      "result means\n"
		      "no evidence was found; it is not proof of absence.",
		      poirot_probe_status_name(report->hwpoint.status),
		      report->hwpoint.error,
		      report->hwpoint.advertised_slots,
		      report->hwpoint.opened_slots,
		      report->hwpoint.enabled_slots,
		      report->hwpoint.signaled_slots,
		      report->hwpoint.returned_slots,
		      report->hwpoint.counted_slots, first_failed_slot);
	return writer.length;
}
