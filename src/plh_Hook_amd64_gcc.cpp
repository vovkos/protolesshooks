#include "plh_Hook.h"
#include "plh_HookCommon.h"
#include "plh_ExecutableBlockArena.h"
#include <string.h>

namespace plh {

//..............................................................................

// nasm -felf64 -lthunk_amd64_gcc.asm.lst thunk_amd64_gcc.asm
// perl nasm-list-to-cpp.pl thunk_amd64_gcc.asm.lst

const uint8_t g_thunkCode[] =
{
	0x55,                                            // 00000000  push    rbp
	0x48, 0x89, 0xE5,                                // 00000001  mov     rbp, rsp
	0x48, 0x81, 0xEC, 0xE0, 0x00, 0x00, 0x00,        // 00000004  sub     rsp, StackFrameSize
	0x66, 0x0F, 0x7F, 0x7D, 0xF0,                    // 0000000B  movdqa  [rbp - 16 * 1], xmm7
	0x66, 0x0F, 0x7F, 0x75, 0xE0,                    // 00000010  movdqa  [rbp - 16 * 2], xmm6
	0x66, 0x0F, 0x7F, 0x6D, 0xD0,                    // 00000015  movdqa  [rbp - 16 * 3], xmm5
	0x66, 0x0F, 0x7F, 0x65, 0xC0,                    // 0000001A  movdqa  [rbp - 16 * 4], xmm4
	0x66, 0x0F, 0x7F, 0x5D, 0xB0,                    // 0000001F  movdqa  [rbp - 16 * 5], xmm3
	0x66, 0x0F, 0x7F, 0x55, 0xA0,                    // 00000024  movdqa  [rbp - 16 * 6], xmm2
	0x66, 0x0F, 0x7F, 0x4D, 0x90,                    // 00000029  movdqa  [rbp - 16 * 7], xmm1
	0x66, 0x0F, 0x7F, 0x45, 0x80,                    // 0000002E  movdqa  [rbp - 16 * 8], xmm0
	0x4C, 0x89, 0x8D, 0x78, 0xFF, 0xFF, 0xFF,        // 00000033  mov     [rbp - 16 * 8 - 8 * 1], r9
	0x4C, 0x89, 0x85, 0x70, 0xFF, 0xFF, 0xFF,        // 0000003A  mov     [rbp - 16 * 8 - 8 * 2], r8
	0x48, 0x89, 0x8D, 0x68, 0xFF, 0xFF, 0xFF,        // 00000041  mov     [rbp - 16 * 8 - 8 * 3], rcx
	0x48, 0x89, 0x95, 0x60, 0xFF, 0xFF, 0xFF,        // 00000048  mov     [rbp - 16 * 8 - 8 * 4], rdx
	0x48, 0x89, 0xB5, 0x58, 0xFF, 0xFF, 0xFF,        // 0000004F  mov     [rbp - 16 * 8 - 8 * 5], rsi
	0x48, 0x89, 0xBD, 0x50, 0xFF, 0xFF, 0xFF,        // 00000056  mov     [rbp - 16 * 8 - 8 * 6], rdi
	0x48, 0xBF,                                      // 0000005D  mov     rdi, hook
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 0000005F
	0x48, 0x89, 0xEE,                                // 00000067  mov     rsi, rbp
	0x48, 0x8B, 0x55, 0x08,                          // 0000006A  mov     rdx, [rbp + 8]
	0x48, 0xB8,                                      // 0000006E  mov     rax, hookEnter
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 00000070
	0xFF, 0xD0,                                      // 00000078  call    rax
	0x48, 0xA9, 0x01, 0x00, 0x00, 0x00,              // 0000007A  test    rax, HookAction_Return
	0x75, 0x7C,                                      // 00000080  jnz     ret_now
	0x66, 0x0F, 0x6F, 0x7D, 0xF0,                    // 00000082  movdqa  xmm7, [rbp - 16 * 1]
	0x66, 0x0F, 0x6F, 0x75, 0xE0,                    // 00000087  movdqa  xmm6, [rbp - 16 * 2]
	0x66, 0x0F, 0x6F, 0x6D, 0xD0,                    // 0000008C  movdqa  xmm5, [rbp - 16 * 3]
	0x66, 0x0F, 0x6F, 0x65, 0xC0,                    // 00000091  movdqa  xmm4, [rbp - 16 * 4]
	0x66, 0x0F, 0x6F, 0x5D, 0xB0,                    // 00000096  movdqa  xmm3, [rbp - 16 * 5]
	0x66, 0x0F, 0x6F, 0x55, 0xA0,                    // 0000009B  movdqa  xmm2, [rbp - 16 * 6]
	0x66, 0x0F, 0x6F, 0x4D, 0x90,                    // 000000A0  movdqa  xmm1, [rbp - 16 * 7]
	0x66, 0x0F, 0x6F, 0x45, 0x80,                    // 000000A5  movdqa  xmm0, [rbp - 16 * 8]
	0x4C, 0x8B, 0x8D, 0x78, 0xFF, 0xFF, 0xFF,        // 000000AA  mov     r9,   [rbp - 16 * 8 - 8 * 1]
	0x4C, 0x8B, 0x85, 0x70, 0xFF, 0xFF, 0xFF,        // 000000B1  mov     r8,   [rbp - 16 * 8 - 8 * 2]
	0x48, 0x8B, 0x8D, 0x68, 0xFF, 0xFF, 0xFF,        // 000000B8  mov     rcx,  [rbp - 16 * 8 - 8 * 3]
	0x48, 0x8B, 0x95, 0x60, 0xFF, 0xFF, 0xFF,        // 000000BF  mov     rdx,  [rbp - 16 * 8 - 8 * 4]
	0x48, 0x8B, 0xB5, 0x58, 0xFF, 0xFF, 0xFF,        // 000000C6  mov     rsi,  [rbp - 16 * 8 - 8 * 5]
	0x48, 0x8B, 0xBD, 0x50, 0xFF, 0xFF, 0xFF,        // 000000CD  mov     rdi,  [rbp - 16 * 8 - 8 * 6]
	0x48, 0x81, 0xC4, 0xE0, 0x00, 0x00, 0x00,        // 000000D4  add     rsp, StackFrameSize
	0x5D,                                            // 000000DB  pop     rbp
	0x48, 0xA9, 0x02, 0x00, 0x00, 0x00,              // 000000DC  test    rax, HookAction_JumpTarget
	0x75, 0x0E,                                      // 000000E2  jnz     jump_target
	0x48, 0xB8,                                      // 000000E4  mov     rax, hookRet
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 000000E6
	0x48, 0x89, 0x04, 0x24,                          // 000000EE  mov     [rsp], rax
	0x48, 0xB8,                                      // 000000F2  mov     rax, targetFunc
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 000000F4
	0xFF, 0xE0,                                      // 000000FC  jmp     rax
	0x66, 0x0F, 0x6F, 0x8D, 0x40, 0xFF, 0xFF, 0xFF,  // 000000FE  movdqa  xmm1, [rbp - RegArgBlockSize - 16 * 1]
	0x66, 0x0F, 0x6F, 0x85, 0x30, 0xFF, 0xFF, 0xFF,  // 00000106  movdqa  xmm0, [rbp - RegArgBlockSize - 16 * 2]
	0x48, 0x8B, 0x95, 0x28, 0xFF, 0xFF, 0xFF,        // 0000010E  mov     rdx,  [rbp - RegArgBlockSize - 16 * 2 - 8 * 1]
	0x48, 0x8B, 0x85, 0x20, 0xFF, 0xFF, 0xFF,        // 00000115  mov     rax,  [rbp - RegArgBlockSize - 16 * 2 - 8 * 2]
	0x48, 0x81, 0xC4, 0xE0, 0x00, 0x00, 0x00,        // 0000011C  add     rsp, StackFrameSize
	0x5D,                                            // 00000123  pop     rbp
	0xC3,                                            // 00000124  ret
	0x48, 0x83, 0xEC, 0x08,                          // 00000125  sub     rsp, 8  ; <<< hookRet
	0x55,                                            // 00000129  push    rbp
	0x48, 0x89, 0xE5,                                // 0000012A  mov     rbp, rsp
	0x48, 0x81, 0xEC, 0xE0, 0x00, 0x00, 0x00,        // 0000012D  sub     rsp, StackFrameSize
	0x66, 0x0F, 0x7F, 0x8D, 0x40, 0xFF, 0xFF, 0xFF,  // 00000134  movdqa  [rbp - RegArgBlockSize - 16 * 1],         xmm1
	0x66, 0x0F, 0x7F, 0x85, 0x30, 0xFF, 0xFF, 0xFF,  // 0000013C  movdqa  [rbp - RegArgBlockSize - 16 * 2],         xmm0
	0x48, 0x89, 0x95, 0x28, 0xFF, 0xFF, 0xFF,        // 00000144  mov     [rbp - RegArgBlockSize - 16 * 2 - 8 * 1], rdx
	0x48, 0x89, 0x85, 0x20, 0xFF, 0xFF, 0xFF,        // 0000014B  mov     [rbp - RegArgBlockSize - 16 * 2 - 8 * 2], rax
	0x48, 0xBF,                                      // 00000152  mov     rdi, hook
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 00000154
	0x48, 0x89, 0xEE,                                // 0000015C  mov     rsi, rbp
	0x48, 0x89, 0xC2,                                // 0000015F  mov     rdx, rax
	0x48, 0xB8,                                      // 00000162  mov     rax, hookLeave
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 00000164
	0xFF, 0xD0,                                      // 0000016C  call    rax
	0x48, 0x89, 0x45, 0x08,                          // 0000016E  mov     [rbp + 8], rax
	0x66, 0x0F, 0x6F, 0x8D, 0x40, 0xFF, 0xFF, 0xFF,  // 00000172  movdqa  xmm1, [rbp - RegArgBlockSize - 16 * 1]
	0x66, 0x0F, 0x6F, 0x85, 0x30, 0xFF, 0xFF, 0xFF,  // 0000017A  movdqa  xmm0, [rbp - RegArgBlockSize - 16 * 2]
	0x48, 0x8B, 0x95, 0x28, 0xFF, 0xFF, 0xFF,        // 00000182  mov     rdx,  [rbp - RegArgBlockSize - 16 * 2 - 8 * 1]
	0x48, 0x8B, 0x85, 0x20, 0xFF, 0xFF, 0xFF,        // 00000189  mov     rax,  [rbp - RegArgBlockSize - 16 * 2 - 8 * 2]
	0x48, 0x81, 0xC4, 0xE0, 0x00, 0x00, 0x00,        // 00000190  add     rsp, StackFrameSize
	0x5D,                                            // 00000197  pop     rbp
	0xC3,                                            // 00000198  ret
};

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

enum ThunkCodeOffset
{
	ThunkCodeOffset_HookPtr1      = 0x005f,
	ThunkCodeOffset_HookEnterPtr  = 0x0070,
	ThunkCodeOffset_HookRetPtr    = 0x00e6,
	ThunkCodeOffset_TargetFuncPtr = 0x00f4,
	ThunkCodeOffset_HookRet       = 0x0125,
	ThunkCodeOffset_HookPtr2      = 0x0154,
	ThunkCodeOffset_HookLeavePtr  = 0x0164,
	ThunkCodeOffset_End           = sizeof(g_thunkCode),
};

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

struct Hook
{
	uint8_t m_thunkCode[(ThunkCodeOffset_End & ~7) + 8]; // align on 8
	HookCommonContext m_context;
};

//..............................................................................

HookAction
hookEnter(
	Hook* hook,
	uint64_t rbp,
	uint64_t originalRet
	)
{
	return hookEnterCommon(&hook->m_context, rbp, originalRet);
}

uint64_t
hookLeave(
	Hook* hook,
	uint64_t rbp
	)
{
	return hookLeaveCommon(&hook->m_context, rbp);
}

//..............................................................................

HookArena::HookArena()
{
	m_impl = new ExecutableBlockArena<Hook>;
}

HookArena::~HookArena()
{
	((ExecutableBlockArena<Hook>*)m_impl)->detach(); // don't free unless explicitly requested
	delete (ExecutableBlockArena<Hook>*)m_impl;
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
	*(void**)(hook->m_thunkCode + ThunkCodeOffset_TargetFuncPtr) = targetFunc;
	*(void**)(hook->m_thunkCode + ThunkCodeOffset_HookRetPtr) = hook->m_thunkCode + ThunkCodeOffset_HookRet;
	*(void**)(hook->m_thunkCode + ThunkCodeOffset_HookEnterPtr) = (void*)hookEnter;
	*(void**)(hook->m_thunkCode + ThunkCodeOffset_HookLeavePtr) = (void*)hookLeave;

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
	*(void**)(hook->m_thunkCode + ThunkCodeOffset_TargetFuncPtr) = targetFunc;
}

//..............................................................................

} // namespace plh
