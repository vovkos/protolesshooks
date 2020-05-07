section .text

	; 1 dword + padding

	STACK_FRAME_SIZE equ 4 + 4

	extern targetFunc
	extern hook
	extern hookEnter
	extern hookLeave
	extern hookRet

thunk_entry:

	; standard prologue (leaves esp 16-byte aligned, ebp 8-byte aligned)

	push    ebp
	mov     ebp, esp
	sub     esp, STACK_FRAME_SIZE

	; call the hook-enter function

	sub     esp, 16
	mov     dword [esp + 0], hook
	mov     [esp + 4], ebp
	mov     eax, [ebp + 4]
	mov     [esp + 8], eax
	mov     eax, hookEnter
	call    eax
	add     esp, 16

	; undo prologue

	add     esp, STACK_FRAME_SIZE
	pop     ebp

	; replace return pointer

	mov     eax, hookRet
	mov     [esp], eax

	; jump to target function

	mov     eax, targetFunc
	jmp     eax

hook_ret:

	; eax now holds the original retval

	; re-create our stack frame (compensating ret from targetFunc)

	sub     esp, 4  ; <<< hook_ret
	push    ebp
	mov     ebp, esp
	sub     esp, STACK_FRAME_SIZE

	; save the original retval

	mov     [ebp - 4], eax

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
	mov     eax, [ebp - 4]

	; standard epilogue

	add     esp, STACK_FRAME_SIZE
	pop     ebp
	ret
