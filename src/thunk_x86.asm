section .text

	; padding + 1 dword

	STACK_FRAME_SIZE equ 4 + 4

	extern targetFunc
	extern hookEnterFunc
	extern hookLeaveFunc
	extern hookRet

thunk_entry:

	; standard prologue

	push    ebp
	mov     ebp, esp
	sub     esp, STACK_FRAME_SIZE

	; call the hook-enter function

	push    targetFunc
	push    ebp
	push    dword [ebp + 4]
	mov     eax, hookEnterFunc
	call    eax

	; undo prologue

	add     esp, STACK_FRAME_SIZE
	pop     ebp

	; replace return pointer

	mov     eax, hookRet
	mov     [esp], eax

	; jump to target function

	mov     eax, targetFunc
	jmp     eax

	; eax now holds the original retval

	; re-create our stack frame (compensating ret from targetFunc)

	sub     esp, 4  ; <<< hook_ret
	push    ebp
	mov     ebp, esp
	sub     esp, STACK_FRAME_SIZE

	; save the original retval

	mov     [ebp - 4], eax

	; call the hook-leave function

	push    targetFunc
	push    ebp
	push    eax
	mov     eax, hookLeaveFunc
	call    eax

	; eax now holds the original return pointer

	; restore the original return pointer and retval

	mov     [ebp + 4], eax
	mov     eax, [ebp - 4]

	; standard epilogue

	add     esp, STACK_FRAME_SIZE
	pop     ebp
	ret
