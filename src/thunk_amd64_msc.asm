section .text

	; 4 gp regs + 4 xmm regs + 4 gp arg home

	STACK_FRAME_SIZE equ 4 * 8 + 4 * 16 + 4 * 8

	extern targetFunc
	extern hook
	extern hookEnterFunc
	extern hookLeaveFunc
	extern hookExceptionFunc
	extern hookRet

thunk_entry:

	; standard prologue (leaves rsp & rpb 16-byte aligned)

	push    rbp
	mov     rbp, rsp
	sub     rsp, STACK_FRAME_SIZE

	; save all arg registers (xmm must be 16-byte aligned)

	movdqa  [rbp - 16 * 1], xmm3
	movdqa  [rbp - 16 * 2], xmm2
	movdqa  [rbp - 16 * 3], xmm1
	movdqa  [rbp - 16 * 4], xmm0
	mov     [rbp - 16 * 4 - 8 * 1], r9
	mov     [rbp - 16 * 4 - 8 * 2], r8
	mov     [rbp - 16 * 4 - 8 * 3], rdx
	mov     [rbp - 16 * 4 - 8 * 4], rcx

	; call the hook-enter function

	mov     rcx, hook
	mov     rdx, rbp
	mov     r8, [rbp + 8]
	mov     rax, hookEnterFunc
	call    rax

	; restore all arg registers

	movdqa  xmm3, [rbp - 16 * 1]
	movdqa  xmm2, [rbp - 16 * 2]
	movdqa  xmm1, [rbp - 16 * 3]
	movdqa  xmm0, [rbp - 16 * 4]
	mov     r9,   [rbp - 16 * 4 - 8 * 1]
	mov     r8,   [rbp - 16 * 4 - 8 * 2]
	mov     rdx,  [rbp - 16 * 4 - 8 * 3]
	mov     rcx,  [rbp - 16 * 4 - 8 * 4]

	; undo prologue

	add     rsp, STACK_FRAME_SIZE
	pop     rbp

	; replace return pointer

	mov     rax, hookRet
	mov     [rsp], rax

	; jump to target function

	mov     rax, targetFunc
	jmp     rax

	; rax now holds the original retval

	; re-create our stack frame (compensating ret from targetFunc)

	sub     rsp, 8  ; <<< hookRet
	push    rbp
	mov     rbp, rsp
	sub     rsp, STACK_FRAME_SIZE

	; save the original retval

	mov     [rbp - 8], rax

	; call the hook-leave function

	mov     rcx, hook
	mov     rdx, rbp
	mov     r8, rax
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

seh_handler:

	; standard prologue (leaves rpb 16-byte aligned)

	push    rbp  ; <<< seh_handler
	mov     rbp, rsp
	sub     rsp, STACK_FRAME_SIZE

	; save rdx (thunk.rbp = rdx - 16)

	mov     [rbp - 8], rdx

	; call the hook-exception function

	mov     rax, hookExceptionFunc
	call    rax

	; rax now holds NULL (for continue) or the original return pointer (for bail)

	test    rax, rax
	jz      seh_epilogue

	; bail -- restore the original return pointer

	mov     rdx,  [rbp - 8]
	mov     [rdx - 16 + 8], rax

	; return ExceptionContinueExecution

	mov     rax, 0

seh_epilogue:

	; standard epilogue

	add     rsp, STACK_FRAME_SIZE
	pop     rbp
	ret
