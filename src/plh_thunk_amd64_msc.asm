section .text

	; reg-arg-home:  4 gp arg regs
	; reg-ret-block: 1 gp ret reg + padding
	; reg-arg-block: 4 gp arg regs + 4 xmm arg regs + 4 gp arg home

	RegArgHomeSize  equ 4 * 8
	RegRetBlockSize equ 1 * 8 + 8
	RegArgBlockSize equ 4 * 8 + 4 * 16
	StackFrameSize  equ RegArgHomeSize + RegRetBlockSize + RegArgBlockSize

	HookAction_Return     equ 1
	HookAction_JumpTarget equ 2

	extern targetFunc
	extern hook
	extern hookEnter
	extern hookLeave
	extern hookException
	extern hookRet

thunk_entry:

	; standard prologue (leaves rsp & rpb 16-byte aligned)

	push    rbp
	mov     rbp, rsp
	sub     rsp, StackFrameSize

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
	mov     rax, hookEnter
	call    rax

	; rax now holds hook action

	test    rax, HookAction_Return
	jnz     ret_now

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

	add     rsp, StackFrameSize
	pop     rbp

	; skip the exit hook?

	test    rax, HookAction_JumpTarget
	jnz     jump_target

	; replace return pointer

	mov     rax, hookRet
	mov     [rsp], rax

jump_target:

	; jump to target function

	mov     rax, targetFunc
	jmp     rax

ret_now:

	; grab rax from the reg-ret-block and return

	mov     rax, [rbp - RegArgBlockSize - RegRetBlockSize]
	ret

hook_ret:

	; rax now holds the original retval

	; re-create our stack frame (compensating ret from targetFunc)

	sub     rsp, 8  ; <<< hookRet
	push    rbp
	mov     rbp, rsp
	sub     rsp, StackFrameSize

	; save the original retval in reg-ret-block

	mov     [rbp - RegArgBlockSize - RegRetBlockSize], rax

	; call the hook-leave function

	mov     rcx, hook
	mov     rdx, rbp
	mov     rax, hookLeave
	call    rax

	; rax now holds the original return pointer

	; restore the original return pointer and retval

	mov     [rbp + 8], rax
	mov     rax, [rbp - RegArgBlockSize - RegRetBlockSize]

	; standard epilogue

	add     rsp, StackFrameSize
	pop     rbp
	ret

seh_handler:

	; standard prologue (leaves rsp & rpb 16-byte aligned)

	push    rbp  ; <<< sehHandler
	mov     rbp, rsp
	sub     rsp, StackFrameSize

	; save rdx (thunk.rbp = rdx - 16)

	mov     [rbp - 8], rdx

	; call the hook-exception function

	mov     rax, hookException
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

	add     rsp, StackFrameSize
	pop     rbp
	ret
