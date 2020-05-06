#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include "protolesshooks.h"

namespace plh {

//..............................................................................

// nasm -felf64 -lthunk_amd64_gcc.asm.lst thunk_amd64_gcc.asm
// perl nasm-list-to-cpp.pl thunk_amd64_gcc.asm.lst

uint8_t g_thunkCode[] =
{
	0x55,                                            // 00000000  push    rbp
	0x48, 0x89, 0xE5,                                // 00000001  mov     rbp, rsp
	0x48, 0x81, 0xEC, 0xC0, 0x00, 0x00, 0x00,        // 00000004  sub     rsp, STACK_FRAME_SIZE
	0x48, 0x89, 0x7D, 0xF0,                          // 0000000B  mov     [rbp - 16 - 8 * 0], rdi
	0x48, 0x89, 0x75, 0xE8,                          // 0000000F  mov     [rbp - 16 - 8 * 1], rsi
	0x48, 0x89, 0x55, 0xE0,                          // 00000013  mov     [rbp - 16 - 8 * 2], rdx
	0x48, 0x89, 0x4D, 0xD8,                          // 00000017  mov     [rbp - 16 - 8 * 3], rcx
	0x4C, 0x89, 0x45, 0xD0,                          // 0000001B  mov     [rbp - 16 - 8 * 4], r8
	0x4C, 0x89, 0x4D, 0xC8,                          // 0000001F  mov     [rbp - 16 - 8 * 5], r9
	0x66, 0x0F, 0x7F, 0x45, 0xC0,                    // 00000023  movdqa  [rbp - 16 - 8 * 6 - 16 * 0], xmm0
	0x66, 0x0F, 0x7F, 0x4D, 0xB0,                    // 00000028  movdqa  [rbp - 16 - 8 * 6 - 16 * 1], xmm1
	0x66, 0x0F, 0x7F, 0x55, 0xA0,                    // 0000002D  movdqa  [rbp - 16 - 8 * 6 - 16 * 2], xmm2
	0x66, 0x0F, 0x7F, 0x5D, 0x90,                    // 00000032  movdqa  [rbp - 16 - 8 * 6 - 16 * 3], xmm3
	0x66, 0x0F, 0x7F, 0x65, 0x80,                    // 00000037  movdqa  [rbp - 16 - 8 * 6 - 16 * 4], xmm4
	0x66, 0x0F, 0x7F, 0xAD, 0x70, 0xFF, 0xFF, 0xFF,  // 0000003C  movdqa  [rbp - 16 - 8 * 6 - 16 * 5], xmm5
	0x66, 0x0F, 0x7F, 0xB5, 0x60, 0xFF, 0xFF, 0xFF,  // 00000044  movdqa  [rbp - 16 - 8 * 6 - 16 * 6], xmm6
	0x66, 0x0F, 0x7F, 0xBD, 0x50, 0xFF, 0xFF, 0xFF,  // 0000004C  movdqa  [rbp - 16 - 8 * 6 - 16 * 7], xmm7
	0x48, 0xBF,                                      // 00000054  mov     rdi, hook
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 00000056
	0x48, 0x89, 0xEE,                                // 0000005E  mov     rsi, rbp
	0x48, 0x8B, 0x55, 0x08,                          // 00000061  mov     rdx, [rbp + 8]
	0x48, 0xB8,                                      // 00000065  mov     rax, hookEnter
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 00000067
	0xFF, 0xD0,                                      // 0000006F  call    rax
	0x48, 0x8B, 0x7D, 0xF0,                          // 00000071  mov     rdi,  [rbp - 16 - 8 * 0]
	0x48, 0x8B, 0x75, 0xE8,                          // 00000075  mov     rsi,  [rbp - 16 - 8 * 1]
	0x48, 0x8B, 0x55, 0xE0,                          // 00000079  mov     rdx,  [rbp - 16 - 8 * 2]
	0x48, 0x8B, 0x4D, 0xD8,                          // 0000007D  mov     rcx,  [rbp - 16 - 8 * 3]
	0x4C, 0x8B, 0x45, 0xD0,                          // 00000081  mov     r8,   [rbp - 16 - 8 * 4]
	0x4C, 0x8B, 0x4D, 0xC8,                          // 00000085  mov     r9,   [rbp - 16 - 8 * 5]
	0x66, 0x0F, 0x6F, 0x45, 0xC0,                    // 00000089  movdqa  xmm0, [rbp - 16 - 8 * 6 - 16 * 0]
	0x66, 0x0F, 0x6F, 0x4D, 0xB0,                    // 0000008E  movdqa  xmm1, [rbp - 16 - 8 * 6 - 16 * 1]
	0x66, 0x0F, 0x6F, 0x55, 0xA0,                    // 00000093  movdqa  xmm2, [rbp - 16 - 8 * 6 - 16 * 2]
	0x66, 0x0F, 0x6F, 0x5D, 0x90,                    // 00000098  movdqa  xmm3, [rbp - 16 - 8 * 6 - 16 * 3]
	0x66, 0x0F, 0x6F, 0x65, 0x80,                    // 0000009D  movdqa  xmm4, [rbp - 16 - 8 * 6 - 16 * 4]
	0x66, 0x0F, 0x6F, 0xAD, 0x70, 0xFF, 0xFF, 0xFF,  // 000000A2  movdqa  xmm5, [rbp - 16 - 8 * 6 - 16 * 5]
	0x66, 0x0F, 0x6F, 0xB5, 0x60, 0xFF, 0xFF, 0xFF,  // 000000AA  movdqa  xmm6, [rbp - 16 - 8 * 6 - 16 * 6]
	0x66, 0x0F, 0x6F, 0xBD, 0x50, 0xFF, 0xFF, 0xFF,  // 000000B2  movdqa  xmm7, [rbp - 16 - 8 * 6 - 16 * 7]
	0x48, 0x81, 0xC4, 0xC0, 0x00, 0x00, 0x00,        // 000000BA  add     rsp, STACK_FRAME_SIZE
	0x5D,                                            // 000000C1  pop     rbp
	0x48, 0xB8,                                      // 000000C2  mov     rax, hookRet
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 000000C4
	0x48, 0x89, 0x04, 0x24,                          // 000000CC  mov     [rsp], rax
	0x48, 0xB8,                                      // 000000D0  mov     rax, targetFunc
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 000000D2
	0xFF, 0xE0,                                      // 000000DA  jmp     rax
	0x48, 0x83, 0xEC, 0x08,                          // 000000DC  sub     rsp, 8  ; <<< hook_ret
	0x55,                                            // 000000E0  push    rbp
	0x48, 0x89, 0xE5,                                // 000000E1  mov     rbp, rsp
	0x48, 0x81, 0xEC, 0xC0, 0x00, 0x00, 0x00,        // 000000E4  sub     rsp, STACK_FRAME_SIZE
	0x48, 0x89, 0x45, 0xF8,                          // 000000EB  mov     [rbp - 8], rax
	0x48, 0xBF,                                      // 000000EF  mov     rdi, hook
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 000000F1
	0x48, 0x89, 0xEE,                                // 000000F9  mov     rsi, rbp
	0x48, 0x89, 0xC2,                                // 000000FC  mov     rdx, rax
	0x48, 0xB8,                                      // 000000FF  mov     rax, hookLeave
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 00000101
	0xFF, 0xD0,                                      // 00000109  call    rax
	0x48, 0x89, 0x45, 0x08,                          // 0000010B  mov     [rbp + 8], rax
	0x48, 0x8B, 0x45, 0xF8,                          // 0000010F  mov     rax, [rbp - 8]
	0x48, 0x81, 0xC4, 0xC0, 0x00, 0x00, 0x00,        // 00000113  add     rsp, STACK_FRAME_SIZE
	0x5D,                                            // 0000011A  pop     rbp
	0xC3,                                            // 0000011B  ret
};

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

enum ThunkCodeOffset
{
	ThunkCodeOffset_HookPtr1      = 0x0056,
	ThunkCodeOffset_HookEnterPtr  = 0x0067,
	ThunkCodeOffset_HookRetPtr    = 0x00c4,
	ThunkCodeOffset_TargetFuncPtr = 0x00d2,
	ThunkCodeOffset_HookRet       = 0x00dc,
	ThunkCodeOffset_HookPtr2      = 0x00f1,
	ThunkCodeOffset_HookLeavePtr  = 0x0101,
	ThunkCodeOffset_End           = sizeof(g_thunkCode),
};

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

struct Hook
{
	uint8_t m_thunkCode[(ThunkCodeOffset_End & ~7) + 8]; // align on 8
	void* m_targetFunc;
	void* m_callbackParam;
	HookEnterFunc* m_enterFunc;
	HookLeaveFunc* m_leaveFunc;
};

//..............................................................................

thread_local uint64_t g_originalRet;

void
hookEnter(
	Hook* hook,
	uint64_t rbp,
	uint64_t originalRet
	)
{
	if (hook->m_enterFunc)
		hook->m_enterFunc(hook->m_targetFunc, hook->m_callbackParam, rbp);

	g_originalRet = originalRet;
}

uint64_t
hookLeave(
	Hook* hook,
	uint64_t rbp,
	uint64_t rax
	)
{
	if (hook->m_leaveFunc)
		hook->m_leaveFunc(hook->m_targetFunc, hook->m_callbackParam, rbp, rax);

	return g_originalRet;
}

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

Hook*
allocateHook(
	void* targetFunc,
	void* callbackParam,
	HookEnterFunc* enterFunc,
	HookLeaveFunc* leaveFunc,
	HookExceptionFunc*
	)
{
	Hook* hook = (Hook*)malloc(sizeof(Hook));
	if (!hook)
		return NULL;

	int pageSize = ::getpagesize();
	size_t pageAddr = (size_t)hook& ~(pageSize - 1);
	int result = ::mprotect((void*)pageAddr, pageSize, PROT_READ | PROT_WRITE | PROT_EXEC);
	if (result != 0)
		return NULL;

	memcpy(hook->m_thunkCode, g_thunkCode, sizeof(g_thunkCode));
	*(void**)(hook->m_thunkCode + ThunkCodeOffset_HookPtr1) = hook;
	*(void**)(hook->m_thunkCode + ThunkCodeOffset_HookPtr2) = hook;
	*(void**)(hook->m_thunkCode + ThunkCodeOffset_TargetFuncPtr) = targetFunc;
	*(void**)(hook->m_thunkCode + ThunkCodeOffset_HookRetPtr) = hook->m_thunkCode + ThunkCodeOffset_HookRet;
	*(void**)(hook->m_thunkCode + ThunkCodeOffset_HookEnterFuncPtr) = (void*)hookEnter;
	*(void**)(hook->m_thunkCode + ThunkCodeOffset_HookLeaveFuncPtr) = (void*)hookLeave;

	hook->m_targetFunc = targetFunc;
	hook->m_callbackParam = callbackParam;
	hook->m_enterFunc = enterFunc;
	hook->m_leaveFunc = leaveFunc;
	return hook;
}

void
freeHook(Hook* hook)
{
	free(hook);
}

//..............................................................................

} // namespace plh
