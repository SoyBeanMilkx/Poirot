	.text

	/* Isolate the control probe from the application page on both 4 KiB
	 * and 16 KiB Android systems. */
	.section .text.hook_control,"ax",%progbits
	.balign 16384
	.global hook_control
	.hidden hook_control
	.type hook_control,%function
hook_control:
	.inst 0xd503245f		/* BTI c */
	add x0, x0, #17
	ret
	.size hook_control, .-hook_control
	.balign 16384

	.section .note.GNU-stack,"",%progbits
