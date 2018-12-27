.bss
.align 16
.comm __stack, 1024 * 1024

.text
.global __start
.extern main
.type __start, @function
.ent __start
.set reorder

__start:
	li $a0, 0
	li $a1, 0
	la $sp, __stack + 1024 * 1024 - 16
	jal main
	li $v0, 0
	li $a0, 0
	syscall

.end __start
.size __start, .-__start

