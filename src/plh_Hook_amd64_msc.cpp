#include "plh_Hook.h"
#include "plh_HookCommon.h"
#include "plh_ThreadState.h"
#include "plh_ExecutableBlockArena.h"

//..............................................................................

// depending on Windows SDK, these declarations may be missing from winnt.h
// prefix structs with PLH_ to avoid name collisions when they ARE in winnt.h

#ifndef UNW_FLAG_EHANDLER
#	define UNW_FLAG_EHANDLER       0x1
#endif

struct PLH_UNWIND_INFO
{
	UCHAR Version       : 3;
	UCHAR Flags         : 5;
	UCHAR SizeOfProlog;
	UCHAR CountOfCodes;
	UCHAR FrameRegister : 4;
	UCHAR FrameOffset   : 4;
};

struct PLH_DISPATCHER_CONTEXT
{
	DWORD64 ControlPc;
	DWORD64 ImageBase;
	PRUNTIME_FUNCTION FunctionEntry;
	DWORD64 EstablisherFrame;
	DWORD64 TargetIp;
	PCONTEXT ContextRecord;
	PEXCEPTION_ROUTINE LanguageHandler;
	PVOID HandlerData;
	PUNWIND_HISTORY_TABLE HistoryTable;
	DWORD ScopeIndex;
	DWORD Fill0;
};

namespace plh {

//..............................................................................

// nasm -fwin64 -lthunk_amd64_msc.asm.lst thunk_amd64_msc.asm
// perl nasm-list-to-cpp.pl thunk_amd64_msc.asm.lst

const uint8_t g_thunkCode[] =
{
	0x55,                                            // 00000000  push    rbp
	0x48, 0x89, 0xE5,                                // 00000001  mov     rbp, rsp
	0x48, 0x81, 0xEC, 0x90, 0x00, 0x00, 0x00,        // 00000004  sub     rsp, StackFrameSize
	0x66, 0x0F, 0x7F, 0x5D, 0xF0,                    // 0000000B  movdqa  [rbp - 16 * 1], xmm3
	0x66, 0x0F, 0x7F, 0x55, 0xE0,                    // 00000010  movdqa  [rbp - 16 * 2], xmm2
	0x66, 0x0F, 0x7F, 0x4D, 0xD0,                    // 00000015  movdqa  [rbp - 16 * 3], xmm1
	0x66, 0x0F, 0x7F, 0x45, 0xC0,                    // 0000001A  movdqa  [rbp - 16 * 4], xmm0
	0x4C, 0x89, 0x4D, 0xB8,                          // 0000001F  mov     [rbp - 16 * 4 - 8 * 1], r9
	0x4C, 0x89, 0x45, 0xB0,                          // 00000023  mov     [rbp - 16 * 4 - 8 * 2], r8
	0x48, 0x89, 0x55, 0xA8,                          // 00000027  mov     [rbp - 16 * 4 - 8 * 3], rdx
	0x48, 0x89, 0x4D, 0xA0,                          // 0000002B  mov     [rbp - 16 * 4 - 8 * 4], rcx
	0x48, 0xB9,                                      // 0000002F  mov     rcx, hook
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 00000031
	0x48, 0x89, 0xEA,                                // 00000039  mov     rdx, rbp
	0x4C, 0x8B, 0x45, 0x08,                          // 0000003C  mov     r8, [rbp + 8]
	0x48, 0xB8,                                      // 00000040  mov     rax, hookEnter
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 00000042
	0xFF, 0xD0,                                      // 0000004A  call    rax
	0x48, 0xA9, 0x01, 0x00, 0x00, 0x00,              // 0000004C  test    rax, HookAction_Return
	0x75, 0x4E,                                      // 00000052  jnz     ret_now
	0x66, 0x0F, 0x6F, 0x5D, 0xF0,                    // 00000054  movdqa  xmm3, [rbp - 16 * 1]
	0x66, 0x0F, 0x6F, 0x55, 0xE0,                    // 00000059  movdqa  xmm2, [rbp - 16 * 2]
	0x66, 0x0F, 0x6F, 0x4D, 0xD0,                    // 0000005E  movdqa  xmm1, [rbp - 16 * 3]
	0x66, 0x0F, 0x6F, 0x45, 0xC0,                    // 00000063  movdqa  xmm0, [rbp - 16 * 4]
	0x4C, 0x8B, 0x4D, 0xB8,                          // 00000068  mov     r9,   [rbp - 16 * 4 - 8 * 1]
	0x4C, 0x8B, 0x45, 0xB0,                          // 0000006C  mov     r8,   [rbp - 16 * 4 - 8 * 2]
	0x48, 0x8B, 0x55, 0xA8,                          // 00000070  mov     rdx,  [rbp - 16 * 4 - 8 * 3]
	0x48, 0x8B, 0x4D, 0xA0,                          // 00000074  mov     rcx,  [rbp - 16 * 4 - 8 * 4]
	0x48, 0x81, 0xC4, 0x90, 0x00, 0x00, 0x00,        // 00000078  add     rsp, StackFrameSize
	0x5D,                                            // 0000007F  pop     rbp
	0x48, 0xA9, 0x02, 0x00, 0x00, 0x00,              // 00000080  test    rax, HookAction_JumpTarget
	0x75, 0x0E,                                      // 00000086  jnz     jump_target
	0x48, 0xB8,                                      // 00000088  mov     rax, hookRet
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 0000008A
	0x48, 0x89, 0x04, 0x24,                          // 00000092  mov     [rsp], rax
	0x48, 0xB8,                                      // 00000096  mov     rax, targetFunc
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 00000098
	0xFF, 0xE0,                                      // 000000A0  jmp     rax
	0x48, 0x8B, 0x45, 0x90,                          // 000000A2  mov     rax, [rbp - RegArgBlockSize - RegRetBlockSize]
	0xC3,                                            // 000000A6  ret
	0x48, 0x83, 0xEC, 0x08,                          // 000000A7  sub     rsp, 8  ; <<< hookRet
	0x55,                                            // 000000AB  push    rbp
	0x48, 0x89, 0xE5,                                // 000000AC  mov     rbp, rsp
	0x48, 0x81, 0xEC, 0x90, 0x00, 0x00, 0x00,        // 000000AF  sub     rsp, StackFrameSize
	0x48, 0x89, 0x45, 0x90,                          // 000000B6  mov     [rbp - RegArgBlockSize - RegRetBlockSize], rax
	0x48, 0xB9,                                      // 000000BA  mov     rcx, hook
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 000000BC
	0x48, 0x89, 0xEA,                                // 000000C4  mov     rdx, rbp
	0x48, 0xB8,                                      // 000000C7  mov     rax, hookLeave
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 000000C9
	0xFF, 0xD0,                                      // 000000D1  call    rax
	0x48, 0x89, 0x45, 0x08,                          // 000000D3  mov     [rbp + 8], rax
	0x48, 0x8B, 0x45, 0x90,                          // 000000D7  mov     rax, [rbp - RegArgBlockSize - RegRetBlockSize]
	0x48, 0x81, 0xC4, 0x90, 0x00, 0x00, 0x00,        // 000000DB  add     rsp, StackFrameSize
	0x5D,                                            // 000000E2  pop     rbp
	0xC3,                                            // 000000E3  ret
	0x55,                                            // 000000E4  push    rbp  ; <<< sehHandler
	0x48, 0x89, 0xE5,                                // 000000E5  mov     rbp, rsp
	0x48, 0x81, 0xEC, 0x90, 0x00, 0x00, 0x00,        // 000000E8  sub     rsp, StackFrameSize
	0x48, 0x89, 0x55, 0xF8,                          // 000000EF  mov     [rbp - 8], rdx
	0x48, 0xB8,                                      // 000000F3  mov     rax, hookException
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 000000F5
	0xFF, 0xD0,                                      // 000000FD  call    rax
	0x48, 0x85, 0xC0,                                // 000000FF  test    rax, rax
	0x74, 0x0D,                                      // 00000102  jz      seh_epilogue
	0x48, 0x8B, 0x55, 0xF8,                          // 00000104  mov     rdx,  [rbp - 8]
	0x48, 0x89, 0x42, 0xF8,                          // 00000108  mov     [rdx - 16 + 8], rax
	0xB8, 0x00, 0x00, 0x00, 0x00,                    // 0000010C  mov     rax, 0
	0x48, 0x81, 0xC4, 0x90, 0x00, 0x00, 0x00,        // 00000111  add     rsp, StackFrameSize
	0x5D,                                            // 00000118  pop     rbp
	0xC3,                                            // 00000119  ret
};

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

enum ThunkCodeOffset
{
	ThunkCodeOffset_HookPtr1         = 0x0031,
	ThunkCodeOffset_HookEnterPtr     = 0x0042,
	ThunkCodeOffset_HookRetPtr       = 0x008a,
	ThunkCodeOffset_TargetFuncPtr    = 0x0098,
	ThunkCodeOffset_HookRet          = 0x00a7,
	ThunkCodeOffset_HookPtr2         = 0x00bc,
	ThunkCodeOffset_HookLeavePtr     = 0x00c9,
	ThunkCodeOffset_HookSehHandler   = 0x00e4,
	ThunkCodeOffset_HookExceptionPtr = 0x00f5,
	ThunkCodeOffset_End              = sizeof(g_thunkCode),
};

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

struct Hook
{
	uint8_t m_thunkCode[(ThunkCodeOffset_End & ~7) + 8]; // align on 8
	RUNTIME_FUNCTION m_runtimeFunction;
	PLH_UNWIND_INFO m_unwindInfo;
	ULONG m_exceptionHandler;
	ULONG m_exceptionHandlerParamPadding;
	HookCommonContext m_commonContext;
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
	while (currentContext.Rsp <= rspLimit)
	{
		uint64_t imageBase;
		RUNTIME_FUNCTION* function = ::RtlLookupFunctionEntry(currentContext.Rip, &imageBase, NULL);

		if (!function)
		{
			uint64_t retRip = *(uint64_t*)currentContext.Rsp;
			if (currentContext.Rip == retRip) // broken stack
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

		if (!exceptionRoutine)
			continue;

		PLH_DISPATCHER_CONTEXT dispatcherContext;
		dispatcherContext.ControlPc = handlerRip;
		dispatcherContext.ImageBase = imageBase;
		dispatcherContext.FunctionEntry = function;
		dispatcherContext.EstablisherFrame = establisherFrame;
		dispatcherContext.ContextRecord = &currentContext;
		dispatcherContext.LanguageHandler = exceptionRoutine;
		dispatcherContext.HandlerData = handlerData;
		dispatcherContext.HistoryTable = NULL;
		dispatcherContext.ScopeIndex = 0;

		enableCurrentThreadHooks(); // exception routine might unwind and never return

		EXCEPTION_DISPOSITION disposition = exceptionRoutine(
			exceptionRecord,
			(void*)establisherFrame,
			exceptionContext,
			&dispatcherContext
			);

		disableCurrentThreadHooks();

		switch (disposition)
		{
		case ExceptionContinueExecution:
			return true;

		case ExceptionContinueSearch:
			break;

		case ExceptionNestedException:
			// shouldn't ever get here -- ExceptionNestedException is returned by RtlpExceptionHandler,
			// but we call a language-specific handler directly (without RtlpExecuteHandlerForException)

			assert(false && "ExceptionNestedException returned by the language-specific handler");
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

HookAction
hookEnter(
	Hook* hook,
	uint64_t rbp,
	uint64_t originalRet
	)
{
	return hookEnterCommon(&hook->m_commonContext, rbp, originalRet);
}

uint64_t
hookLeave(
	Hook* hook,
	uint64_t rbp
	)
{
	return hookLeaveCommon(&hook->m_commonContext, rbp);
}

uint64_t
hookException(
	EXCEPTION_RECORD* exceptionRecord,
	uint64_t establisherFrame,
	CONTEXT* contextRecord,
	PLH_DISPATCHER_CONTEXT* dispatcherContext
	)
{
	disableCurrentThreadHooks();

	ThreadState* threadState = getCurrentThreadState(false);
	assert(threadState && "missing thread-state in seh-hook");

	Hook* hook = CONTAINING_RECORD(dispatcherContext->HandlerData, Hook, m_exceptionHandlerParamPadding);
	uint64_t rbp = establisherFrame - 2 * 8;

	if (hook->m_exceptionFunc)
		hook->m_exceptionFunc(
			hook->m_commonContext.m_targetFunc,
			hook->m_commonContext.m_callbackParam,
			rbp,
			exceptionRecord,
			contextRecord
			);

	uint64_t originalRet = threadState->getOriginalRet(rbp);
	if (!originalRet)
		return -1; // no need to enable, we are about to crash and burn

	bool result = dispatchException(
		exceptionRecord,
		contextRecord,
		originalRet,
		establisherFrame
		);

	enableCurrentThreadHooks();
	return result ? 0 : originalRet; // returning NULL means ExceptionContinueExecution
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
	*(void**)(hook->m_thunkCode + ThunkCodeOffset_HookExceptionPtr) = (void*)hookException;

	hook->m_runtimeFunction.BeginAddress = 0;
	hook->m_runtimeFunction.EndAddress = sizeof(g_thunkCode);
	hook->m_runtimeFunction.UnwindData = FIELD_OFFSET(Hook, m_unwindInfo);

	hook->m_unwindInfo.Version = 1;
	hook->m_unwindInfo.Flags = UNW_FLAG_EHANDLER;
	hook->m_unwindInfo.SizeOfProlog = 0;
	hook->m_unwindInfo.FrameRegister = 0;
	hook->m_unwindInfo.FrameOffset = 0;
	hook->m_unwindInfo.CountOfCodes = 0;

	hook->m_exceptionHandler = ThunkCodeOffset_HookSehHandler;
	hook->m_commonContext.m_targetFunc = targetFunc;
	hook->m_commonContext.m_callbackParam = callbackParam;
	hook->m_commonContext.m_enterFunc = enterFunc;
	hook->m_commonContext.m_leaveFunc = leaveFunc;
	hook->m_exceptionFunc = NULL;

	uint64_t baseAddress = (uint64_t)hook;
	::RtlAddFunctionTable(&hook->m_runtimeFunction, 1, baseAddress);
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

void
setHookExceptionFunc(
	Hook* hook,
	HookExceptionFunc* exceptionFunc
	)
{
	hook->m_exceptionFunc = exceptionFunc;
}

//..............................................................................

} // namespace plh
