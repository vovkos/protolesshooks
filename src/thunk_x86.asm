section .text

	; reg-ret-block: 2 gp reg
	; reg-arg-block: 3 gp regs + padding

	RegRetBlockSize equ 2 * 4
	RegArgBlockSize equ 3 * 4 + 4
	StackFrameSize  equ RegRetBlockSize + RegArgBlockSize

	HookAction_Return     equ 1
	HookAction_JumpTarget equ 2

	extern targetFunc
	extern hook
	extern hookEnter
	extern hookLeave
	extern hookRet

thunk_entry:

	; standard prologue (leaves esp 16-byte aligned, ebp 8-byte aligned)

	push    ebp
	mov     ebp, esp
	sub     esp, StackFrameSize

	; save all arg registers

	mov     [ebp - 4 * 2], eax
	mov     [ebp - 4 * 3], edx
	mov     [ebp - 4 * 4], ecx

	; call the hook-enter function

	sub     esp, 16
	mov     dword [esp + 0], hook
	mov     [esp + 4], ebp
	mov     eax, [ebp + 4]
	mov     [esp + 8], eax
	call    hookEnter
	add     esp, 16

	; eax now holds hook action

	test    eax, HookAction_Return
	jnz     ret_now

	test    eax, HookAction_JumpTarget
	jnz     jump_target

	; replace return pointer

	mov     dword [esp + StackFrameSize + 4], hookRet

jump_target:

	; restore all arg registers

	mov     eax, [ebp - 4 * 2]
	mov     edx, [ebp - 4 * 3]
	mov     ecx, [ebp - 4 * 4]

	; undo prologue

	add     esp, StackFrameSize
	pop     ebp

	; jump to target function

	jmp     targetFunc

ret_now:

	; grab retval regs from the reg-ret-block

	mov     edx, [ebp - RegArgBlockSize - 4 * 1]
	mov     eax, [ebp - RegArgBlockSize - 4 * 2]

	; standard epilogue

	add     esp, StackFrameSize
	pop     ebp
	ret

hook_ret:

	; eax now holds the original retval

	; re-create our stack frame (compensating ret from targetFunc)

	sub     esp, 4  ; <<< hookRet
	push    ebp
	mov     ebp, esp
	sub     esp, StackFrameSize

	; save the original retval

	mov     [ebp - RegArgBlockSize - 4 * 1], edx
	mov     [ebp - RegArgBlockSize - 4 * 2], eax

	; call the hook-leave function

	sub     esp, 16
	mov     dword [esp + 0], hook
	mov     [esp + 4], ebp
	call    hookLeave
	add     esp, 16

	; eax now holds the original return pointer

	; restore the original return pointer and retval regs

	mov     [ebp + 4], eax

	mov     edx, [ebp - RegArgBlockSize - 4 * 1]
	mov     eax, [ebp - RegArgBlockSize - 4 * 2]

	; standard epilogue

	add     esp, StackFrameSize
	pop     ebp
	ret
