#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include "protolesshooks.h"
#include "plh_HookMgr.h"

namespace plh {

//..............................................................................

// nasm -felf64 -lthunk_amd64_gcc.asm.lst thunk_amd64_gcc.asm
// perl nasm-list-to-cpp.pl thunk_amd64_gcc.asm.lst

uint8_t g_thunkCode[] =
{
	0x55,                                            // 00000000  push    rbp
	0x48, 0x89, 0xE5,                                // 00000001  mov     rbp, rsp
	0x48, 0x81, 0xEC, 0xB0, 0x00, 0x00, 0x00,        // 00000004  sub     rsp, STACK_FRAME_SIZE
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
	0x66, 0x0F, 0x6F, 0x7D, 0xF0,                    // 0000007A  movdqa  xmm7, [rbp - 16 * 1]
	0x66, 0x0F, 0x6F, 0x75, 0xE0,                    // 0000007F  movdqa  xmm6, [rbp - 16 * 2]
	0x66, 0x0F, 0x6F, 0x6D, 0xD0,                    // 00000084  movdqa  xmm5, [rbp - 16 * 3]
	0x66, 0x0F, 0x6F, 0x65, 0xC0,                    // 00000089  movdqa  xmm4, [rbp - 16 * 4]
	0x66, 0x0F, 0x6F, 0x5D, 0xB0,                    // 0000008E  movdqa  xmm3, [rbp - 16 * 5]
	0x66, 0x0F, 0x6F, 0x55, 0xA0,                    // 00000093  movdqa  xmm2, [rbp - 16 * 6]
	0x66, 0x0F, 0x6F, 0x4D, 0x90,                    // 00000098  movdqa  xmm1, [rbp - 16 * 7]
	0x66, 0x0F, 0x6F, 0x45, 0x80,                    // 0000009D  movdqa  xmm0, [rbp - 16 * 8]
	0x4C, 0x8B, 0x8D, 0x78, 0xFF, 0xFF, 0xFF,        // 000000A2  mov     r9,   [rbp - 16 * 8 - 8 * 1]
	0x4C, 0x8B, 0x85, 0x70, 0xFF, 0xFF, 0xFF,        // 000000A9  mov     r8,   [rbp - 16 * 8 - 8 * 2]
	0x48, 0x8B, 0x8D, 0x68, 0xFF, 0xFF, 0xFF,        // 000000B0  mov     rcx,  [rbp - 16 * 8 - 8 * 3]
	0x48, 0x8B, 0x95, 0x60, 0xFF, 0xFF, 0xFF,        // 000000B7  mov     rdx,  [rbp - 16 * 8 - 8 * 4]
	0x48, 0x8B, 0xB5, 0x58, 0xFF, 0xFF, 0xFF,        // 000000BE  mov     rsi,  [rbp - 16 * 8 - 8 * 5]
	0x48, 0x8B, 0xBD, 0x50, 0xFF, 0xFF, 0xFF,        // 000000C5  mov     rdi,  [rbp - 16 * 8 - 8 * 6]
	0x48, 0x81, 0xC4, 0xB0, 0x00, 0x00, 0x00,        // 000000CC  add     rsp, STACK_FRAME_SIZE
	0x5D,                                            // 000000D3  pop     rbp
	0x48, 0xB8,                                      // 000000D4  mov     rax, hookRet
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 000000D6
	0x48, 0x89, 0x04, 0x24,                          // 000000DE  mov     [rsp], rax
	0x48, 0xB8,                                      // 000000E2  mov     rax, targetFunc
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 000000E4
	0xFF, 0xE0,                                      // 000000EC  jmp     rax
	0x48, 0x83, 0xEC, 0x08,                          // 000000EE  sub     rsp, 8  ; <<< hookRet
	0x55,                                            // 000000F2  push    rbp
	0x48, 0x89, 0xE5,                                // 000000F3  mov     rbp, rsp
	0x48, 0x81, 0xEC, 0xB0, 0x00, 0x00, 0x00,        // 000000F6  sub     rsp, STACK_FRAME_SIZE
	0x48, 0x89, 0x45, 0xF8,                          // 000000FD  mov     [rbp - 8], rax
	0x48, 0xBF,                                      // 00000101  mov     rdi, hook
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 00000103
	0x48, 0x89, 0xEE,                                // 0000010B  mov     rsi, rbp
	0x48, 0x89, 0xC2,                                // 0000010E  mov     rdx, rax
	0x48, 0xB8,                                      // 00000111  mov     rax, hookLeave
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 00000113
	0xFF, 0xD0,                                      // 0000011B  call    rax
	0x48, 0x89, 0x45, 0x08,                          // 0000011D  mov     [rbp + 8], rax
	0x48, 0x8B, 0x45, 0xF8,                          // 00000121  mov     rax, [rbp - 8]
	0x48, 0x81, 0xC4, 0xB0, 0x00, 0x00, 0x00,        // 00000125  add     rsp, STACK_FRAME_SIZE
	0x5D,                                            // 0000012C  pop     rbp
	0xC3,                                            // 0000012D  ret
};

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

enum ThunkCodeOffset
{
	ThunkCodeOffset_HookPtr1      = 0x005f,
	ThunkCodeOffset_HookEnterPtr  = 0x0070,
	ThunkCodeOffset_HookRetPtr    = 0x00d6,
	ThunkCodeOffset_TargetFuncPtr = 0x00e4,
	ThunkCodeOffset_HookRet       = 0x00ee,
	ThunkCodeOffset_HookPtr2      = 0x0103,
	ThunkCodeOffset_HookLeavePtr  = 0x0113,
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

thread_local HookMgr g_hookMgr;

void
hookEnter(
	Hook* hook,
	uint64_t rbp,
	uint64_t originalRet
	)
{
	if (hook->m_enterFunc)
		hook->m_enterFunc(hook->m_targetFunc, hook->m_callbackParam, rbp);

	g_hookMgr.addFrame(rbp, originalRet);
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

	return g_hookMgr.removeFrame(rbp);
}

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

Hook*
allocateHook(
	void* targetFunc,
	void* callbackParam,
	HookEnterFunc* enterFunc,
	HookLeaveFunc* leaveFunc
	)
{
	Hook* hook = (Hook*)malloc(sizeof(Hook));
	if (!hook)
		return NULL;

	int pageSize = ::getpagesize();
	size_t pageAddr = (size_t)hook & ~(pageSize - 1);
	int result = ::mprotect((void*)pageAddr, pageSize, PROT_READ | PROT_WRITE | PROT_EXEC);
	if (result != 0)
		return NULL;

	memcpy(hook->m_thunkCode, g_thunkCode, sizeof(g_thunkCode));
	*(void**)(hook->m_thunkCode + ThunkCodeOffset_HookPtr1) = hook;
	*(void**)(hook->m_thunkCode + ThunkCodeOffset_HookPtr2) = hook;
	*(void**)(hook->m_thunkCode + ThunkCodeOffset_TargetFuncPtr) = targetFunc;
	*(void**)(hook->m_thunkCode + ThunkCodeOffset_HookRetPtr) = hook->m_thunkCode + ThunkCodeOffset_HookRet;
	*(void**)(hook->m_thunkCode + ThunkCodeOffset_HookEnterPtr) = (void*)hookEnter;
	*(void**)(hook->m_thunkCode + ThunkCodeOffset_HookLeavePtr) = (void*)hookLeave;

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
