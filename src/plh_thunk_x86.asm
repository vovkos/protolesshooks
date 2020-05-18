section .text

	; reg-ret-block: 1 gp reg + padding

	RegRetBlockSize equ 4 + 4
	StackFrameSize  equ RegRetBlockSize

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

	; call the hook-enter function

	sub     esp, 16
	mov     dword [esp + 0], hook
	mov     [esp + 4], ebp
	mov     eax, [ebp + 4]
	mov     [esp + 8], eax
	mov     eax, hookEnter
	call    eax
	add     esp, 16

	; eax now holds hook action

	test    eax, HookAction_Return
	jnz     ret_now

	; undo prologue

	add     esp, StackFrameSize
	pop     ebp

	; skip the exit hook?

	test    eax, HookAction_JumpTarget
	jnz     jump_target

	; replace return pointer

	mov     eax, hookRet
	mov     [esp], eax

jump_target:

	; jump to target function

	mov     eax, targetFunc
	jmp     eax

ret_now:

	; grab rax from the reg-ret-block and return

	mov     eax, [ebp - RegRetBlockSize]
	ret

hook_ret:

	; eax now holds the original retval

	; re-create our stack frame (compensating ret from targetFunc)

	sub     esp, 4  ; <<< hookRet
	push    ebp
	mov     ebp, esp
	sub     esp, StackFrameSize

	; save the original retval

	mov     [ebp - RegRetBlockSize], eax

	; call the hook-leave function

	sub     esp, 16
	mov     dword [esp + 0], hook
	mov     [esp + 4], ebp
	mov     [esp + 8], eax
	mov     eax, hookLeave
	call    eax
	add     esp, 16

	; eax now holds the original return pointer

	; restore the original return pointer and retval

	mov     [ebp + 4], eax
	mov     eax, [ebp - RegRetBlockSize]

	; standard epilogue

	add     esp, StackFrameSize
	pop     ebp
	ret
