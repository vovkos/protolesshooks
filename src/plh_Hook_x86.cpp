#include "plh_Hook.h"
#include "plh_HookCommon.h"
#include "plh_ExecutableBlockArena.h"
#include <string.h>

namespace plh {

//..............................................................................

// nasm -fwin32 -lthunk_x86.asm.lst thunk_x86.asm
// perl nasm-list-to-cpp.pl thunk_x86.asm.lst

const uint8_t g_thunkCode[] =
{
	0x55,                                            // 00000000  push    ebp
	0x89, 0xE5,                                      // 00000001  mov     ebp, esp
	0x83, 0xEC, 0x18,                                // 00000003  sub     esp, StackFrameSize
	0x89, 0x45, 0xFC,                                // 00000006  mov     [ebp - 4 * 1], eax
	0x89, 0x55, 0xF8,                                // 00000009  mov     [ebp - 4 * 2], edx
	0x89, 0x4D, 0xF4,                                // 0000000C  mov     [ebp - 4 * 3], ecx
	0x83, 0xEC, 0x10,                                // 0000000F  sub     esp, 16
	0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,        // 00000012  mov     dword [esp + 0], hook
	0x89, 0x6C, 0x24, 0x04,                          // 00000019  mov     [esp + 4], ebp
	0x8B, 0x45, 0x04,                                // 0000001D  mov     eax, [ebp + 4]
	0x89, 0x44, 0x24, 0x08,                          // 00000020  mov     [esp + 8], eax
	0xE8, 0x00, 0x00, 0x00, 0x00,                    // 00000024  call    hookEnter
	0x83, 0xC4, 0x10,                                // 00000029  add     esp, 16
	0xA9, 0x01, 0x00, 0x00, 0x00,                    // 0000002C  test    eax, HookAction_Return
	0x75, 0x21,                                      // 00000031  jnz     ret_now
	0xA9, 0x02, 0x00, 0x00, 0x00,                    // 00000033  test    eax, HookAction_JumpTarget
	0x75, 0x08,                                      // 00000038  jnz     jump_target
	0xC7, 0x44, 0x24, 0x1C, 0x00, 0x00, 0x00, 0x00,  // 0000003A  mov     dword [esp + StackFrameSize + 4], hookRet
	0x8B, 0x45, 0xFC,                                // 00000042  mov     eax, [ebp - 4 * 1]
	0x8B, 0x55, 0xF8,                                // 00000045  mov     edx, [ebp - 4 * 2]
	0x8B, 0x4D, 0xF4,                                // 00000048  mov     ecx, [ebp - 4 * 3]
	0x83, 0xC4, 0x18,                                // 0000004B  add     esp, StackFrameSize
	0x5D,                                            // 0000004E  pop     ebp
	0xE9, 0x00, 0x00, 0x00, 0x00,                    // 0000004F  jmp     targetFunc
	0x8B, 0x55, 0xEC,                                // 00000054  mov     edx, [ebp - RegArgBlockSize - 4 * 1]
	0x8B, 0x45, 0xE8,                                // 00000057  mov     eax, [ebp - RegArgBlockSize - 4 * 2]
	0x83, 0xC4, 0x18,                                // 0000005A  add     esp, StackFrameSize
	0x5D,                                            // 0000005D  pop     ebp
	0xC3,                                            // 0000005E  ret
	0x83, 0xEC, 0x04,                                // 0000005F  sub     esp, 4  ; <<< hookRet
	0x55,                                            // 00000062  push    ebp
	0x89, 0xE5,                                      // 00000063  mov     ebp, esp
	0x83, 0xEC, 0x18,                                // 00000065  sub     esp, StackFrameSize
	0x89, 0x55, 0xEC,                                // 00000068  mov     [ebp - RegArgBlockSize - 4 * 1], edx
	0x89, 0x45, 0xE8,                                // 0000006B  mov     [ebp - RegArgBlockSize - 4 * 2], eax
	0x83, 0xEC, 0x10,                                // 0000006E  sub     esp, 16
	0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,        // 00000071  mov     dword [esp + 0], hook
	0x89, 0x6C, 0x24, 0x04,                          // 00000078  mov     [esp + 4], ebp
	0xE8, 0x00, 0x00, 0x00, 0x00,                    // 0000007C  call    hookLeave
	0x83, 0xC4, 0x10,                                // 00000081  add     esp, 16
	0x89, 0x45, 0x04,                                // 00000084  mov     [ebp + 4], eax
	0x8B, 0x55, 0xEC,                                // 00000087  mov     edx, [ebp - RegArgBlockSize - 4 * 1]
	0x8B, 0x45, 0xE8,                                // 0000008A  mov     eax, [ebp - RegArgBlockSize - 4 * 2]
	0x83, 0xC4, 0x18,                                // 0000008D  add     esp, StackFrameSize
	0x5D,                                            // 00000090  pop     ebp
	0xC3,                                            // 00000091  ret
};

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

enum ThunkCodeOffset
{
	ThunkCodeOffset_HookPtr1      = 0x15,
	ThunkCodeOffset_CallHookEnter = 0x24,
	ThunkCodeOffset_HookRetPtr    = 0x3e,
	ThunkCodeOffset_JmpTargetFunc = 0x4f,
	ThunkCodeOffset_HookRet       = 0x5f,
	ThunkCodeOffset_HookPtr2      = 0x74,
	ThunkCodeOffset_CallHookLeave = 0x7c,
	ThunkCodeOffset_End           = sizeof(g_thunkCode),
};

//..............................................................................

struct Hook
{
	uint8_t m_thunkCode[(ThunkCodeOffset_End & ~7) + 8]; // align on 8
	HookCommonContext m_context;
};

//..............................................................................

HookAction
hookEnter(
	Hook* hook,
	uint32_t ebp,
	uint32_t originalRet
	)
{
	return hookEnterCommon(&hook->m_context, ebp, originalRet);
}

uint32_t
hookLeave(
	Hook* hook,
	uint32_t ebp
	)
{
	return hookLeaveCommon(&hook->m_context, ebp);
}

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

HookArena::HookArena()
{
	m_impl = new ExecutableBlockArena<Hook>;
}

HookArena::~HookArena()
{
	((ExecutableBlockArena<Hook>*)m_impl)->detach(); // don't free unless explicitly requested
	delete (ExecutableBlockArena<Hook>*)m_impl;
}

inline
void
setCallJmpRel32Target(
	uint8_t* code,
	size_t offset,
	void* target
	)
{
	// CALL rel32 =>  e8 xx xx xx xx
	// JMP  rel32 =>  e9 xx xx xx xx
	// rel32 is relative to EIP after the instruction

	*(uint32_t*)(code + offset + 1) = (uint8_t*)target - (code + offset + 5);
}

Hook*
HookArena::allocate(
	void* targetFunc,
	void* callbackParam,
	HookEnterFunc* enterFunc,
	HookLeaveFunc* leaveFunc
)
{
	Hook* hook = ((ExecutableBlockArena<Hook>*)m_impl)->allocate();
	if (!hook)
		return NULL;

	memcpy(hook->m_thunkCode, g_thunkCode, sizeof(g_thunkCode));
	*(void**)(hook->m_thunkCode + ThunkCodeOffset_HookPtr1) = hook;
	*(void**)(hook->m_thunkCode + ThunkCodeOffset_HookPtr2) = hook;
	*(void**)(hook->m_thunkCode + ThunkCodeOffset_HookRetPtr) = hook->m_thunkCode + ThunkCodeOffset_HookRet;

	setCallJmpRel32Target(hook->m_thunkCode, ThunkCodeOffset_CallHookEnter, (void*)hookEnter);
	setCallJmpRel32Target(hook->m_thunkCode, ThunkCodeOffset_JmpTargetFunc, (void*)targetFunc);
	setCallJmpRel32Target(hook->m_thunkCode, ThunkCodeOffset_CallHookLeave, (void*)hookLeave);

	hook->m_context.m_targetFunc = targetFunc;
	hook->m_context.m_callbackParam = callbackParam;
	hook->m_context.m_enterFunc = enterFunc;
	hook->m_context.m_leaveFunc = leaveFunc;
	return hook;
}

void
HookArena::free()
{
	((ExecutableBlockArena<Hook>*)m_impl)->free();
}

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

void
setHookTargetFunc(
	Hook* hook,
	void* targetFunc
)
{
	setCallJmpRel32Target(hook->m_thunkCode, ThunkCodeOffset_JmpTargetFunc, (void*)targetFunc);
}

//..............................................................................

} // namespace plh
