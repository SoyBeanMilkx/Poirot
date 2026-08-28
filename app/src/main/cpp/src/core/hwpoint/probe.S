	.text
	.p2align 2

	.macro HWPOINT_PROBE index
	.global hwpoint_probe_\index
	.hidden hwpoint_probe_\index
	.type hwpoint_probe_\index,%function
hwpoint_probe_\index:
	.inst 0xd503245f		/* BTI c */
	mov w0, #0
	ret
	.size hwpoint_probe_\index, .-hwpoint_probe_\index
	.endm

	HWPOINT_PROBE 0
	HWPOINT_PROBE 1
	HWPOINT_PROBE 2
	HWPOINT_PROBE 3
	HWPOINT_PROBE 4
	HWPOINT_PROBE 5
	HWPOINT_PROBE 6
	HWPOINT_PROBE 7
	HWPOINT_PROBE 8
	HWPOINT_PROBE 9
	HWPOINT_PROBE 10
	HWPOINT_PROBE 11
	HWPOINT_PROBE 12
	HWPOINT_PROBE 13
	HWPOINT_PROBE 14
	HWPOINT_PROBE 15

	.section .note.GNU-stack,"",%progbits
