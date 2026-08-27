	.text

	/* Isolate the control probe from the application page on both 4 KiB
	 * and 16 KiB Android systems. */
	.section .text.poirot_hook_control,"ax",%progbits
	.balign 16384
	.global poirot_hook_control
	.hidden poirot_hook_control
	.type poirot_hook_control,%function
poirot_hook_control:
	.inst 0xd503245f		/* BTI c */
	add x0, x0, #17
	ret
	.size poirot_hook_control, .-poirot_hook_control
	.balign 16384

	.section .note.GNU-stack,"",%progbits
