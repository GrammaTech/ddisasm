	.text

# prefer global to weak and local
.type	_fun_local, @function
_fun_local:

.weak _fun
.type	_fun, @function
_fun:

.globl	no_fun
.type	no_fun, @notype
no_fun:

.globl	fun
.type	fun, @function
fun:

	ret


	.globl	main
	.type	main, @function
main:
.LFB6:
	pushq	%rbp
	movq	%rsp, %rbp
	movl	$20, %esi
	movl	$10, %edi
	call	fun
Block_hello:
	leaq	hello_not_hidden(%rip), %rdi
	call	puts@PLT
Block_how:
	leaq	how_global(%rip), %rdi
	call	puts@PLT
Block_bye:
	leaq	bye_obj(%rip), %rdi
	call	puts@PLT
	movl	$0, %eax
	popq	%rbp
	ret

.LFE6:
	.size	main, .-main


	.section	.rodata

# hello is preferred over hello_local and hello_hidden
hello_local:
	.globl hello_hidden
	.hidden hello_hidden
hello_hidden:
	.globl hello_not_hidden
hello_not_hidden:

	.string	"!!!Hello World!!!"

# global preferred over weak

.weak how_a
.type	how_a, @object
how_a:
.globl	how_global
.type	how_global, @object
how_global:
.weak how_weak
.type	how_weak, @object
how_weak:

	.string	"How are you?"

# prefer object type over notype
.type bye_notype, @notype
bye_notype:
.type bye_obj, @object
bye_obj:
	.string	"Bye bye"
end_of_data_section:
