section .text

	; padding + 6 gp regs + 8 xmm regs

	STACK_FRAME_SIZE equ 16 + 6 * 8 + 8 * 16 

	extern targetFunc
	extern hookEnterFunc
	extern hookLeaveFunc
	extern hookRet

thunk_entry:

	; standard prologue (leaves rsp & rpb 16-byte aligned)

	push    rbp
	mov     rbp, rsp
	sub     rsp, STACK_FRAME_SIZE

	; save all arg registers (xmm must be 16-byte aligned)

	mov     [rbp - 16 - 8 * 0], rdi
	mov     [rbp - 16 - 8 * 1], rsi
	mov     [rbp - 16 - 8 * 2], rdx
	mov     [rbp - 16 - 8 * 3], rcx
	mov     [rbp - 16 - 8 * 4], r8
	mov     [rbp - 16 - 8 * 5], r9
	movdqa  [rbp - 16 - 8 * 6 - 16 * 0], xmm0
	movdqa  [rbp - 16 - 8 * 6 - 16 * 1], xmm1
	movdqa  [rbp - 16 - 8 * 6 - 16 * 2], xmm2
	movdqa  [rbp - 16 - 8 * 6 - 16 * 3], xmm3
	movdqa  [rbp - 16 - 8 * 6 - 16 * 4], xmm4
	movdqa  [rbp - 16 - 8 * 6 - 16 * 5], xmm5
	movdqa  [rbp - 16 - 8 * 6 - 16 * 6], xmm6
	movdqa  [rbp - 16 - 8 * 6 - 16 * 7], xmm7

	; call the hook-enter function

	mov     rdi, targetFunc
	mov     rsi, rbp
	mov     rdx, [rbp + 8]
	mov     rax, hookEnterFunc
	call    rax

	; restore all arg registers

	mov     rdi,  [rbp - 16 - 8 * 0]
	mov     rsi,  [rbp - 16 - 8 * 1]
	mov     rdx,  [rbp - 16 - 8 * 2]
	mov     rcx,  [rbp - 16 - 8 * 3]
	mov     r8,   [rbp - 16 - 8 * 4]
	mov     r9,   [rbp - 16 - 8 * 5]
	movdqa  xmm0, [rbp - 16 - 8 * 6 - 16 * 0]
	movdqa  xmm1, [rbp - 16 - 8 * 6 - 16 * 1]
	movdqa  xmm2, [rbp - 16 - 8 * 6 - 16 * 2]
	movdqa  xmm3, [rbp - 16 - 8 * 6 - 16 * 3]
	movdqa  xmm4, [rbp - 16 - 8 * 6 - 16 * 4]
	movdqa  xmm5, [rbp - 16 - 8 * 6 - 16 * 5]
	movdqa  xmm6, [rbp - 16 - 8 * 6 - 16 * 6]
	movdqa  xmm7, [rbp - 16 - 8 * 6 - 16 * 7]

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

	sub     rsp, 8  ; <<< hook_ret
	push    rbp
	mov     rbp, rsp
	sub     rsp, STACK_FRAME_SIZE

	; save the original retval

	mov     [rbp - 8], rax

	; call the hook-leave function

	mov     rdi, targetFunc
	mov     rsi, rbp
	mov     rdx, rax
	mov     rax, hookLeaveFunc
	call    rax

	; rax now holds the original return pointer

	; restore the original return pointer and retval

	mov     [rbp + 8], rax
	mov     rax, [rbp - 8]

	; standard epilogue

	add     rsp, STACK_FRAME_SIZE
	pop     rbp
	ret
