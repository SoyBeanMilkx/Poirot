#include "poirot.h"

#include "src/crypto/md5.h"

#include <inttypes.h>
#include <jni.h>
#include <stdio.h>
#include <unistd.h>

static _Thread_local uint32_t business_hits;

__attribute__((noinline, visibility("default")))
uint64_t business_md5(uint64_t input) {
	business_hits = POIROT_HOOK_CHECK(POIROT_CHECK_DIAGNOSTIC);
	return md5_u64(input);
}

static const char *business_check_name(uint32_t hits, uint32_t check,
			       uint32_t selected) {
	if (!(selected & check))
		return "skipped";
	return hits & check ? "hit" : "no hit";
}

JNIEXPORT jstring JNICALL Java_com_yuuki_poirot_MainActivity_nativeDescribe(
	JNIEnv *environment, jobject instance) {
	size_t page_size;
	uintptr_t page;
	char text[512];

	(void)instance;
	{
		long value = sysconf(_SC_PAGESIZE);

		page_size = value > 0 ? (size_t)value : 4096;
	}
	page = (uintptr_t)business_md5 -
	       (uintptr_t)business_md5 % page_size;
	(void)snprintf(text, sizeof(text),
		       "Poirot is ready.\n\n"
		       "Hook business_md5 with wxshadow or pte_hook, then run "
		       "detection.\n"
		       "target    = 0x%" PRIxPTR "\n"
		       "target page = 0x%" PRIxPTR "\n"
		       "page size = %zu",
		       (uintptr_t)business_md5, page, page_size);
	return (*environment)->NewStringUTF(environment, text);
}

JNIEXPORT jstring JNICALL Java_com_yuuki_poirot_MainActivity_nativeRunDetection(
	JNIEnv *environment, jobject instance) {
	const uint32_t selected = POIROT_CHECK_DIAGNOSTIC;
	const uint64_t input = UINT64_C(0x504f4952);
	char text[3072];
	uint64_t expected;
	uint64_t result;
	uint32_t hits;

	(void)instance;
	business_hits = 0;
	result = business_md5(input);
	hits = business_hits;
	expected = md5_u64(input);
	(void)snprintf(
		text, sizeof(text),
		"Poirot hook check\n"
		"verdict: %s   mask: 0x%03" PRIx32 "\n"
		"shadow hits: %u/5   redirect hits: %u/3\n\n"
		"business\n"
		"  function : business_md5\n"
		"  address  : 0x%" PRIxPTR "\n"
		"  input    : 0x%016" PRIx64 "\n"
		"  expected : 0x%016" PRIx64 "\n"
		"  result   : 0x%016" PRIx64 " (%s)\n\n"
		"1. timing    : %s\n"
		"2. self-read : %s\n"
		"3. mprotect  : %s\n"
		"4. parallel  : %s\n"
		"5. fork      : %s\n"
		"6. fault PC  : %s\n"
		"7. signal PC : %s\n"
		"8. ghost page: %s\n\n"
		"The protected business function calls POIROT_HOOK_CHECK() "
		"before MD5.",
		poirot_hook_hits_detected(hits)
			? "detected"
			: hits ? "anomalous" : "clean",
		hits,
		poirot_hook_hit_count(hits & POIROT_CHECK_SHADOW_ALL),
		poirot_hook_hit_count(hits & POIROT_CHECK_REDIRECT_ALL),
		(uintptr_t)business_md5,
		input, expected, result,
		result == expected ? "correct" : "mismatch",
		business_check_name(hits, POIROT_CHECK_TIMING, selected),
		business_check_name(hits, POIROT_CHECK_SELFREAD, selected),
		business_check_name(hits, POIROT_CHECK_PROTECT, selected),
		business_check_name(hits, POIROT_CHECK_PARALLEL, selected),
		business_check_name(hits, POIROT_CHECK_FORK, selected),
		business_check_name(hits, POIROT_CHECK_REDIRECT_FAULT,
				    selected),
		business_check_name(hits, POIROT_CHECK_REDIRECT_SIGNAL,
				    selected),
		business_check_name(hits, POIROT_CHECK_REDIRECT_GHOST,
				    selected));
	return (*environment)->NewStringUTF(environment, text);
}
