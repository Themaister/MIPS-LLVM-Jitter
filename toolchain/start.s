.bss
.align 12
.comm __stack, 1024 * 1024

.text
.set reorder

.global __start
.extern main
.type __start, @function
.ent __start

__start:
	li $a0, 0
	li $a1, 0
	la $sp, __stack + 1024 * 1024 - 16
	jal main

	li $a0, 0
	jal exit

.end __start
.size __start, .-__start

.macro create_syscall call, code
.global \call
.extern \call
.type \call, @function
.ent \call

\call:
	li $v0, \code
	syscall
	jr $ra

.end \call
.size \call, .-\call
.endm

create_syscall exit 4001
create_syscall write 4004
create_syscall read 4003

