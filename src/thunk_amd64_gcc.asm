section .text

	; 6 gp regs + 8 xmm regs

	STACK_FRAME_SIZE equ 6 * 8 + 8 * 16

	extern targetFunc
	extern hook
	extern hookEnter
	extern hookLeave
	extern hookRet

thunk_entry:

	; standard prologue (leaves rsp & rpb 16-byte aligned)

	push    rbp
	mov     rbp, rsp
	sub     rsp, STACK_FRAME_SIZE

	; save all arg registers (xmm must be 16-byte aligned)

	movdqa  [rbp - 16 * 1], xmm7
	movdqa  [rbp - 16 * 2], xmm6
	movdqa  [rbp - 16 * 3], xmm5
	movdqa  [rbp - 16 * 4], xmm4
	movdqa  [rbp - 16 * 5], xmm3
	movdqa  [rbp - 16 * 6], xmm2
	movdqa  [rbp - 16 * 7], xmm1
	movdqa  [rbp - 16 * 8], xmm0
	mov     [rbp - 16 * 8 - 8 * 1], r9
	mov     [rbp - 16 * 8 - 8 * 2], r8
	mov     [rbp - 16 * 8 - 8 * 3], rcx
	mov     [rbp - 16 * 8 - 8 * 4], rdx
	mov     [rbp - 16 * 8 - 8 * 5], rsi
	mov     [rbp - 16 * 8 - 8 * 6], rdi

	; call the hook-enter function

	mov     rdi, hook
	mov     rsi, rbp
	mov     rdx, [rbp + 8]
	mov     rax, hookEnter
	call    rax

	; restore all arg registers

	movdqa  xmm7, [rbp - 16 * 1]
	movdqa  xmm6, [rbp - 16 * 2]
	movdqa  xmm5, [rbp - 16 * 3]
	movdqa  xmm4, [rbp - 16 * 4]
	movdqa  xmm3, [rbp - 16 * 5]
	movdqa  xmm2, [rbp - 16 * 6]
	movdqa  xmm1, [rbp - 16 * 7]
	movdqa  xmm0, [rbp - 16 * 8]
	mov     r9,   [rbp - 16 * 8 - 8 * 1]
	mov     r8,   [rbp - 16 * 8 - 8 * 2]
	mov     rcx,  [rbp - 16 * 8 - 8 * 3]
	mov     rdx,  [rbp - 16 * 8 - 8 * 4]
	mov     rsi,  [rbp - 16 * 8 - 8 * 5]
	mov     rdi,  [rbp - 16 * 8 - 8 * 6]

	; undo prologue

	add     rsp, STACK_FRAME_SIZE
	pop     rbp

	; replace return pointer

	mov     rax, hookRet
	mov     [rsp], rax

	; jump to target function

	mov     rax, targetFunc
	jmp     rax

hook_ret:

	; rax now holds the original retval

	; re-create our stack frame (compensating ret from targetFunc)

	sub     rsp, 8  ; <<< hookRet
	push    rbp
	mov     rbp, rsp
	sub     rsp, STACK_FRAME_SIZE

	; save the original retval

	mov     [rbp - 8], rax

	; call the hook-leave function

	mov     rdi, hook
	mov     rsi, rbp
	mov     rdx, rax
	mov     rax, hookLeave
	call    rax

	; rax now holds the original return pointer

	; restore the original return pointer and retval

	mov     [rbp + 8], rax
	mov     rax, [rbp - 8]

	; standard epilogue

	add     rsp, STACK_FRAME_SIZE
	pop     rbp
	ret
