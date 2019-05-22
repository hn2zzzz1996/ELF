	.file	"lpv64.c"
	.text
	.globl	_start
	.type	_start, @function
_start:
.LFB2:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
#APP
# 21 "lpv64.c" 1
	.globl real_start
real_start:
push %rax
push %rcx
push %rdx
push %rbx
push %rsp
push %rbp
push %rsi
push %rdi
call do_main
pop %rdi
pop %rsi
pop %rbp
pop %rsp
pop %rbx
pop %rbx
pop %rcx
pop %rax
jmp myexit

# 0 "" 2
#NO_APP
	nop
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE2:
	.size	_start, .-_start
	.section	.rodata
.LC0:
	.string	"hello"
	.text
	.globl	do_main
	.type	do_main, @function
do_main:
.LFB3:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$1056, %rsp
	movq	%fs:40, %rax
	movq	%rax, -8(%rbp)
	xorl	%eax, %eax
	call	get_rip
	movq	%rax, %rcx
	movl	foobar(%rip), %eax
	movslq	%eax, %rdx
	movl	real_start(%rip), %eax
	cltq
	subq	%rax, %rdx
	movq	%rdx, %rax
	subq	%rax, %rcx
	movq	%rcx, %rax
	movq	%rax, -1048(%rbp)
	movl	myexit(%rip), %eax
	movl	%eax, %edx
	movl	real_start(%rip), %eax
	subl	%eax, %edx
	movl	%edx, %eax
	movl	%eax, -1052(%rbp)
	addl	$7, -1052(%rbp)
	movb	$46, -1040(%rbp)
	movb	$0, -1039(%rbp)
	movl	$5, %edx
	movl	$.LC0, %esi
	movl	$1, %edi
	call	write
	nop
	movq	-8(%rbp), %rsi
	xorq	%fs:40, %rsi
	je	.L3
	call	__stack_chk_fail
.L3:
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE3:
	.size	do_main, .-do_main
	.globl	get_rip
	.type	get_rip, @function
get_rip:
.LFB4:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
#APP
# 82 "lpv64.c" 1
	.globl foobar
call foobar
foobar:pop %rax
# 0 "" 2
#NO_APP
	nop
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE4:
	.size	get_rip, .-get_rip
	.globl	write
	.type	write, @function
write:
.LFB5:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movl	%edi, -20(%rbp)
	movq	%rsi, -32(%rbp)
	movq	%rdx, -40(%rbp)
	movl	-20(%rbp), %eax
	movslq	%eax, %rdx
	movq	-32(%rbp), %rcx
	movq	-40(%rbp), %rsi
	movl	$1, %eax
#APP
# 114 "lpv64.c" 1
	mov %eax, %rdi
mov %rdx, %rsi
mov %rcx, %rdx
syscall
# 0 "" 2
#NO_APP
	movq	%rax, -8(%rbp)
	movq	-8(%rbp), %rax
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE5:
	.size	write, .-write
	.globl	exit_code
	.type	exit_code, @function
exit_code:
.LFB6:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
#APP
# 117 "lpv64.c" 1
	.globl myexit
myexit:
mov $60, %rax
mov $0, %rdi
syscall

# 0 "" 2
#NO_APP
	nop
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE6:
	.size	exit_code, .-exit_code
	.ident	"GCC: (Ubuntu 5.4.0-6ubuntu1~16.04.11) 5.4.0 20160609"
	.section	.note.GNU-stack,"",@progbits
