#include <stdint.h>
#include <windows.h>
#include <assert.h>

#include "protolesshooks.h"

//..............................................................................

// missing declaration from winnt.h

struct UNWIND_INFO
{
	UCHAR Version       : 3;
	UCHAR Flags         : 5;
	UCHAR SizeOfProlog;
	UCHAR CountOfCodes;
	UCHAR FrameRegister : 4;
	UCHAR FrameOffset   : 4;
};

namespace plh {

//..............................................................................

// nasm -fwin64 -lthunk_amd64_msc.asm.lst thunk_amd64_msc.asm
// perl nasm-list-to-cpp.pl thunk_amd64_msc.asm.lst

uint8_t g_thunkCode[] =
{
	0x55,                                            // 00000000  push    rbp
	0x48, 0x89, 0xE5,                                // 00000001  mov     rbp, rsp
	0x48, 0x81, 0xEC, 0x90, 0x00, 0x00, 0x00,        // 00000004  sub     rsp, STACK_FRAME_SIZE
	0x48, 0x89, 0x4D, 0xF0,                          // 0000000B  mov     [rbp - 16 - 8 * 0], rcx
	0x48, 0x89, 0x55, 0xE8,                          // 0000000F  mov     [rbp - 16 - 8 * 1], rdx
	0x4C, 0x89, 0x45, 0xE0,                          // 00000013  mov     [rbp - 16 - 8 * 2], r8
	0x4C, 0x89, 0x4D, 0xD8,                          // 00000017  mov     [rbp - 16 - 8 * 3], r9
	0x66, 0x0F, 0x7F, 0x45, 0xD0,                    // 0000001B  movdqa  [rbp - 16 - 8 * 4 - 16 * 0], xmm0
	0x66, 0x0F, 0x7F, 0x4D, 0xC0,                    // 00000020  movdqa  [rbp - 16 - 8 * 4 - 16 * 1], xmm1
	0x66, 0x0F, 0x7F, 0x55, 0xB0,                    // 00000025  movdqa  [rbp - 16 - 8 * 4 - 16 * 2], xmm2
	0x66, 0x0F, 0x7F, 0x5D, 0xA0,                    // 0000002A  movdqa  [rbp - 16 - 8 * 4 - 16 * 3], xmm3
	0x48, 0xB9,                                      // 0000002F  mov     rcx, hook
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 00000031
	0x48, 0x89, 0xEA,                                // 00000039  mov     rdx, rbp
	0x4C, 0x8B, 0x45, 0x08,                          // 0000003C  mov     r8, [rbp + 8]
	0x48, 0xB8,                                      // 00000040  mov     rax, hookEnterFunc
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 00000042
	0xFF, 0xD0,                                      // 0000004A  call    rax
	0x48, 0x8B, 0x4D, 0xF0,                          // 0000004C  mov     rcx,  [rbp - 16 - 8 * 0]
	0x48, 0x8B, 0x55, 0xE8,                          // 00000050  mov     rdx,  [rbp - 16 - 8 * 1]
	0x4C, 0x8B, 0x45, 0xE0,                          // 00000054  mov     r8,   [rbp - 16 - 8 * 2]
	0x4C, 0x8B, 0x4D, 0xD8,                          // 00000058  mov     r9,   [rbp - 16 - 8 * 3]
	0x66, 0x0F, 0x6F, 0x45, 0xD0,                    // 0000005C  movdqa  xmm0, [rbp - 16 - 8 * 4 - 16 * 0]
	0x66, 0x0F, 0x6F, 0x4D, 0xC0,                    // 00000061  movdqa  xmm1, [rbp - 16 - 8 * 4 - 16 * 1]
	0x66, 0x0F, 0x6F, 0x55, 0xB0,                    // 00000066  movdqa  xmm2, [rbp - 16 - 8 * 4 - 16 * 2]
	0x66, 0x0F, 0x6F, 0x5D, 0xA0,                    // 0000006B  movdqa  xmm3, [rbp - 16 - 8 * 4 - 16 * 3]
	0x48, 0x81, 0xC4, 0x90, 0x00, 0x00, 0x00,        // 00000070  add     rsp, STACK_FRAME_SIZE
	0x5D,                                            // 00000077  pop     rbp
	0x48, 0xB8,                                      // 00000078  mov     rax, hookRet
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 0000007A
	0x48, 0x89, 0x04, 0x24,                          // 00000082  mov     [rsp], rax
	0x48, 0xB8,                                      // 00000086  mov     rax, targetFunc
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 00000088
	0xFF, 0xE0,                                      // 00000090  jmp     rax
	0x48, 0x83, 0xEC, 0x08,                          // 00000092  sub     rsp, 8  ; <<< hookRet
	0x55,                                            // 00000096  push    rbp
	0x48, 0x89, 0xE5,                                // 00000097  mov     rbp, rsp
	0x48, 0x81, 0xEC, 0x90, 0x00, 0x00, 0x00,        // 0000009A  sub     rsp, STACK_FRAME_SIZE
	0x48, 0x89, 0x45, 0xF8,                          // 000000A1  mov     [rbp - 8], rax
	0x48, 0xB9,                                      // 000000A5  mov     rcx, hook
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 000000A7
	0x48, 0x89, 0xEA,                                // 000000AF  mov     rdx, rbp
	0x49, 0x89, 0xC0,                                // 000000B2  mov     r8, rax
	0x48, 0xB8,                                      // 000000B5  mov     rax, hookLeaveFunc
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 000000B7
	0xFF, 0xD0,                                      // 000000BF  call    rax
	0x48, 0x89, 0x45, 0x08,                          // 000000C1  mov     [rbp + 8], rax
	0x48, 0x8B, 0x45, 0xF8,                          // 000000C5  mov     rax, [rbp - 8]
	0x48, 0x81, 0xC4, 0x90, 0x00, 0x00, 0x00,        // 000000C9  add     rsp, STACK_FRAME_SIZE
	0x5D,                                            // 000000D0  pop     rbp
	0xC3,                                            // 000000D1  ret
	0x55,                                            // 000000D2  push    rbp  ; <<< seh_handler
	0x48, 0x89, 0xE5,                                // 000000D3  mov     rbp, rsp
	0x48, 0x81, 0xEC, 0x90, 0x00, 0x00, 0x00,        // 000000D6  sub     rsp, STACK_FRAME_SIZE
	0x48, 0x89, 0x55, 0xF8,                          // 000000DD  mov     [rbp - 8], rdx
	0x48, 0xB8,                                      // 000000E1  mov     rax, hookExceptionFunc
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 000000E3
	0xFF, 0xD0,                                      // 000000EB  call    rax
	0x48, 0x85, 0xC0,                                // 000000ED  test    rax, rax
	0x74, 0x0D,                                      // 000000F0  jz      seh_epilogue
	0x48, 0x8B, 0x55, 0xF8,                          // 000000F2  mov     rdx,  [rbp - 8]
	0x48, 0x89, 0x42, 0xF8,                          // 000000F6  mov     [rdx - 16 + 8], rax
	0xB8, 0x00, 0x00, 0x00, 0x00,                    // 000000FA  mov     rax, 0
	0x48, 0x81, 0xC4, 0x90, 0x00, 0x00, 0x00,        // 000000FF  add     rsp, STACK_FRAME_SIZE
	0x5D,                                            // 00000106  pop     rbp
	0xC3,                                            // 00000107  ret
};

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

enum ThunkCodeOffset
{
	ThunkCodeOffset_HookPtr1             = 0x31,
	ThunkCodeOffset_HookEnterFuncPtr     = 0x42,
	ThunkCodeOffset_HookRetPtr           = 0x7a,
	ThunkCodeOffset_TargetFuncPtr        = 0x88,
	ThunkCodeOffset_HookRet              = 0x92,
	ThunkCodeOffset_HookPtr2             = 0xa7,
	ThunkCodeOffset_HookLeaveFuncPtr     = 0xb7,
	ThunkCodeOffset_HookSehHandler       = 0xd2,
	ThunkCodeOffset_HookExceptionFuncPtr = 0xe3,
	ThunkCodeOffset_End                  = sizeof(g_thunkCode),
};

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

struct Hook
{
	uint8_t m_thunkCode[(ThunkCodeOffset_End & ~7) + 8]; // align on 8
	RUNTIME_FUNCTION m_runtimeFunction;
	UNWIND_INFO m_unwindInfo;
	ULONG m_exceptionHandler;
	ULONG m_exceptionHandlerParamPadding;
	void* m_targetFunc;
	void* m_callbackParam;
	HookEnterFunc* m_enterFunc;
	HookLeaveFunc* m_leaveFunc;
	HookExceptionFunc* m_exceptionFunc;
};

//..............................................................................

// a simplified version of RtlDispatchException

bool
dispatchException(
    EXCEPTION_RECORD* exceptionRecord,
	CONTEXT* exceptionContext,
	uint64_t rip0,
	uint64_t rsp0
    )
{
	CONTEXT currentContext = *exceptionContext;
	currentContext.Rip = rip0;
	currentContext.Rsp = rsp0;

	uint64_t rspLimit = (uint64_t)((NT_TIB*)NtCurrentTeb())->StackBase;
	for (size_t i = 0; currentContext.Rsp <= rspLimit; i++)
	{
		uint64_t imageBase;
		RUNTIME_FUNCTION* function = ::RtlLookupFunctionEntry(currentContext.Rip, &imageBase, NULL);

		if (!function)
		{
			uint64_t retRip = *(uint64_t*)currentContext.Rsp;
			if (currentContext.Rip == retRip) // broken stack (will cause infinite loop)
				break;

            currentContext.Rip = retRip;
            currentContext.Rsp += 8;
			continue;
		}

		void* functionBase = (char*)imageBase + function->BeginAddress;

		void* handlerData;
		uint64_t handlerRip = currentContext.Rip;
		uint64_t handlerRsp = currentContext.Rsp;
		uint64_t establisherFrame;

		EXCEPTION_ROUTINE* exceptionRoutine = ::RtlVirtualUnwind(
			UNW_FLAG_EHANDLER,
			imageBase,
			handlerRip,
			function,
			&currentContext,
			&handlerData,
			&establisherFrame,
			NULL
			);

		if (handlerRsp >= currentContext.Rsp) // broken stack (rsp must grow)
			break;

		if (!exceptionRoutine || !i) // skip the first handler (it's us)
			continue;

	    DISPATCHER_CONTEXT dispatcherContext;
		dispatcherContext.ControlPc = handlerRip;
		dispatcherContext.ImageBase = imageBase;
		dispatcherContext.FunctionEntry = function;
		dispatcherContext.EstablisherFrame = establisherFrame;
		dispatcherContext.ContextRecord = &currentContext;
		dispatcherContext.LanguageHandler = exceptionRoutine;
		dispatcherContext.HandlerData = handlerData;
		dispatcherContext.HistoryTable = NULL;
		dispatcherContext.ScopeIndex = 0;

		EXCEPTION_DISPOSITION disposition = exceptionRoutine(
			exceptionRecord,
			(void*)establisherFrame,
			exceptionContext,
			&dispatcherContext
			);

		switch (disposition)
		{
		case ExceptionContinueExecution:
			return true;

		case ExceptionContinueSearch:
			break;

		case ExceptionNestedException:
			// shouldn't ever get here -- ExceptionNestedException is returned by RtlpExceptionHandler,
			// but we call a language-specific handler directly (without RtlpExecuteHandlerForException)

			assert(false);
			return false;

		case ExceptionCollidedUnwind:
			// an edge-case, really, so not critical to process (maybe later). for now -- just bail.

		default:
			// bail -- restore the original return-ip (thus removing our hook) and retry exception
			return false;
		}
	}

	// we run beyond the stack base -- bail
	return false;
}

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

uint64_t
hookException(
	EXCEPTION_RECORD* exceptionRecord,
	uint64_t establisherFrame,
	CONTEXT* contextRecord,
	DISPATCHER_CONTEXT* dispatcherContext
	)
{
	Hook* hook = CONTAINING_RECORD(dispatcherContext->HandlerData, Hook, m_exceptionHandlerParamPadding);
	uint64_t rbp = establisherFrame - 2 * 8;

	if (hook->m_exceptionFunc)
		hook->m_exceptionFunc(
			hook->m_targetFunc,
			hook->m_callbackParam,
			rbp,
			exceptionRecord,
			contextRecord
			);

	bool result = dispatchException(
		exceptionRecord,
		contextRecord,
		g_originalRet,
		establisherFrame
		);

	return result ? NULL : g_originalRet; // returning NULL means ExceptionContinueExecution
}

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

Hook*
allocateHook(
	void* targetFunc,
	void* callbackParam,
	HookEnterFunc* enterFunc,
	HookLeaveFunc* leaveFunc,
	HookExceptionFunc* exceptionFunc
	)
{
	Hook* hook = (Hook*)::VirtualAlloc(
		NULL,
		sizeof(Hook),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
		);

	if (!hook)
		return NULL;

	memcpy(hook->m_thunkCode, g_thunkCode, sizeof(g_thunkCode));
	*(void**)(hook->m_thunkCode + ThunkCodeOffset_HookPtr1) = hook;
	*(void**)(hook->m_thunkCode + ThunkCodeOffset_HookPtr2) = hook;
	*(void**)(hook->m_thunkCode + ThunkCodeOffset_TargetFuncPtr) = targetFunc;
	*(void**)(hook->m_thunkCode + ThunkCodeOffset_HookRetPtr) = hook->m_thunkCode + ThunkCodeOffset_HookRet;
	*(void**)(hook->m_thunkCode + ThunkCodeOffset_HookEnterFuncPtr) = (void*)hookEnter;
	*(void**)(hook->m_thunkCode + ThunkCodeOffset_HookLeaveFuncPtr) = (void*)hookLeave;
	*(void**)(hook->m_thunkCode + ThunkCodeOffset_HookExceptionFuncPtr) = (void*)hookException;

	hook->m_runtimeFunction.BeginAddress = 0;
	hook->m_runtimeFunction.EndAddress = sizeof(g_thunkCode);
	hook->m_runtimeFunction.UnwindInfoAddress = FIELD_OFFSET(Hook, m_unwindInfo);

	hook->m_unwindInfo.Version = 1;
	hook->m_unwindInfo.Flags = UNW_FLAG_EHANDLER;
	hook->m_unwindInfo.SizeOfProlog = 0;
	hook->m_unwindInfo.FrameRegister = 0;
	hook->m_unwindInfo.FrameOffset = 0;
	hook->m_unwindInfo.CountOfCodes = 0;

	hook->m_exceptionHandler = ThunkCodeOffset_HookSehHandler;
	hook->m_targetFunc = targetFunc;
	hook->m_callbackParam = callbackParam;
	hook->m_enterFunc = enterFunc;
	hook->m_leaveFunc = leaveFunc;
	hook->m_exceptionFunc = exceptionFunc;

	uint64_t baseAddress = (uint64_t)hook;
	::RtlAddFunctionTable(&hook->m_runtimeFunction, 1, baseAddress);
	return hook;
}

void
freeHook(Hook* hook)
{
	::VirtualFree(hook, sizeof(Hook), MEM_RELEASE);
}

//..............................................................................

} // namespace plh
