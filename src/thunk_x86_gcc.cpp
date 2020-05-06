#include <stdint.h>

//..............................................................................

// nasm -fwin32 -lthunk_x86.asm.lst thunk_x86.asm
// perl nasm-list-to-cpp.pl thunk_x86.asm.lst

uint8_t g_thunkCode[] =
{
	0x55,                          // 00000000  push    ebp
	0x89, 0xE5,                    // 00000001  mov     ebp, esp
	0x83, 0xEC, 0x0C,              // 00000003  sub     esp, STACK_FRAME_SIZE
	0x68, 0x00, 0x00, 0x00, 0x00,  // 00000006  push    targetFunc
	0x55,                          // 0000000B  push    ebp
	0xFF, 0x75, 0x04,              // 0000000C  push    dword [ebp + 4]
	0xB8, 0x00, 0x00, 0x00, 0x00,  // 0000000F  mov     eax, hookEnterFunc
	0xFF, 0xD0,                    // 00000014  call    eax
	0x83, 0xC4, 0x0C,              // 00000016  add     esp, STACK_FRAME_SIZE
	0x5D,                          // 00000019  pop     ebp
	0xB8, 0x00, 0x00, 0x00, 0x00,  // 0000001A  mov     eax, hookRet
	0x89, 0x04, 0x24,              // 0000001F  mov     [esp], eax
	0xB8, 0x00, 0x00, 0x00, 0x00,  // 00000022  mov     eax, targetFunc
	0xFF, 0xE0,                    // 00000027  jmp     eax
	0x83, 0xEC, 0x04,              // 00000029  sub     esp, 4  ; <<< hook_ret
	0x55,                          // 0000002C  push    ebp
	0x89, 0xE5,                    // 0000002D  mov     ebp, esp
	0x83, 0xEC, 0x0C,              // 0000002F  sub     esp, STACK_FRAME_SIZE
	0x89, 0x45, 0xFC,              // 00000032  mov     [ebp - 4], eax
	0x68, 0x00, 0x00, 0x00, 0x00,  // 00000035  push    targetFunc
	0x55,                          // 0000003A  push    ebp
	0x50,                          // 0000003B  push    eax
	0xB8, 0x00, 0x00, 0x00, 0x00,  // 0000003C  mov     eax, hookLeaveFunc
	0xFF, 0xD0,                    // 00000041  call    eax
	0x89, 0x45, 0x04,              // 00000043  mov     [ebp + 4], eax
	0x8B, 0x45, 0xFC,              // 00000046  mov     eax, [ebp - 4]
	0x83, 0xC4, 0x0C,              // 00000049  add     esp, STACK_FRAME_SIZE
	0x5D,                          // 0000004C  pop     ebp
	0xC3,                          // 0000004D  ret
};

//..............................................................................

#if (WIN32)

#pragma pack(pop)

struct Thunk
{
	ThunkCode m_code;
#if (WIN32)
	RUNTIME_FUNCTION m_runtimeFunction;
	UNWIND_INFO m_unwindInfo;
	ULONG m_exceptionHandler;
	VOID* m_exceptionParam;
#endif
};

//..............................................................................

#else

#pragma pack(push, 1)

union ThunkCode
{
	enum
	{
		StackFrameSize = 8 + 6 * 8 + 8 * 16, // padding + 6 gp regs + 8 xmm regs
	};

	uint8_t m_code[0x11c];

	struct
	{
		uint8_t m_offset1[0x56];
		uint64_t m_targetFunc1;
	};

	struct
	{
		uint8_t m_offset2[0x67];
		uint64_t m_hookEnterFunc;
	};

	struct
	{
		uint8_t m_offset3[0xc4];
		uint64_t m_hookRet;
	};

	struct
	{
		uint8_t m_offset4[0xd2];
		uint64_t m_targetFunc2;
	};

	struct
	{
		uint8_t m_hookRetOffset[0xdc];
	};

	struct
	{
		uint8_t m_offset5[0xf1];
		uint64_t m_targetFunc3;
	};

	struct
	{
		uint8_t m_offset6[0x101];
		uint64_t m_hookLeaveFunc;
	};
};

// nasm -f elf64 -l thunk_systemv_amd64.asm.lst thunk_systemv_amd64.asm

ThunkCode g_thunkCodeTemplate =
{{
	0x55,                                            // 00000000  push    rbp
	0x48, 0x89, 0xE5,                                // 00000001  mov     rbp, rsp
	0x48, 0x81, 0xEC, 0xB8, 0x00, 0x00, 0x00,        // 00000004  sub     rsp, STACK_FRAME_SIZE
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
	0x48, 0xBF,                                      // 00000054  mov     rdi, targetFunc
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 00000056
	0x48, 0x89, 0xEE,                                // 0000005E  mov     rsi, rbp
	0x48, 0x8B, 0x55, 0x08,                          // 00000061  mov     rdx, [rbp + 8]
	0x48, 0xB8,                                      // 00000065  mov     rax, hookEnterFunc
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
	0x48, 0x81, 0xC4, 0xB8, 0x00, 0x00, 0x00,        // 000000BA  add     rsp, STACK_FRAME_SIZE
	0x5D,                                            // 000000C1  pop     rbp
	0x48, 0xB8,                                      // 000000C2  mov     rax, hookRet
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 000000C4
	0x48, 0x89, 0x04, 0x24,                          // 000000CC  mov     [rsp], rax
	0x48, 0xB8,                                      // 000000D0  mov     rax, targetFunc
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 000000D2
	0xFF, 0xE0,                                      // 000000DA  jmp     rax
	0x48, 0x83, 0xEC, 0x08,                          // 000000DC  sub     rsp, 8                 ; <<< hookRet
	0x55,                                            // 000000E0  push    rbp
	0x48, 0x89, 0xE5,                                // 000000E1  mov     rbp, rsp
	0x48, 0x81, 0xEC, 0xB8, 0x00, 0x00, 0x00,        // 000000E4  sub     rsp, STACK_FRAME_SIZE
	0x48, 0x89, 0x45, 0xF8,                          // 000000EB  mov     [rbp - 8], rax
	0x48, 0xBF,                                      // 000000EF  mov     rdi, targetFunc
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 000000F1
	0x48, 0x89, 0xEE,                                // 000000F9  mov     rsi, rbp
	0x48, 0x89, 0xC2,                                // 000000FC  mov     rdx, rax
	0x48, 0xB8,                                      // 000000FF  mov     rax, hookLeaveFunc
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 00000101
	0xFF, 0xD0,                                      // 00000109  call    rax
	0x48, 0x89, 0x45, 0x08,                          // 0000010B  mov     [rbp + 8], rax
	0x48, 0x8B, 0x45, 0xF8,                          // 0000010F  mov     rax, [rbp - 8]
	0x48, 0x81, 0xC4, 0xB8, 0x00, 0x00, 0x00,        // 00000113  add     rsp, STACK_FRAME_SIZE
	0x5D,                                            // 0000011A  pop     rbp
	0xC3,                                            // 0000011B  ret
}};

#pragma pack(pop)

struct Thunk
{
	ThunkCode m_code;
};

#endif

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

int* g_p = NULL;
int g_x;

thread_local void* g_originalRet;

void
hookEnter(
	void* func,
	void* rbp,
	void* originalRet
	)
{
	printf("hookEnter(func: %p, rbp: %p, [rsp]: %p)\n", func, rbp, originalRet);
	g_originalRet = originalRet;
}

void*
hookLeave(
	void* func,
	void* rbp,
	void* rax
	)
{
	printf("hookLeave(func: %p, rbp: %p, rax: %lld / 0x%p)\n", func, rbp, (uint64_t)rax, rax);
	return g_originalRet;
}

#if (_AXL_OS_WIN)

void*
hookException(
	EXCEPTION_RECORD* exceptionRecord,
	void* establisherFrame,
	CONTEXT* contextRecord,
	DISPATCHER_CONTEXT* dispatcherContext
	)
{
	void* func = *(void**)dispatcherContext->HandlerData;
	void* rbp = (void**)establisherFrame - 2;
	printf("hookException(func: %p, rbp: %p)\n", func, rbp);
	return g_originalRet;
}

#endif

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

Thunk*
createThunk(void* targetFunc)
{
#if (WIN32)
	Thunk* thunk = (Thunk*)::VirtualAlloc(
		NULL,
		sizeof(Thunk),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
		);
#else
	Thunk* thunk = (Thunk*)malloc(sizeof(Thunk));
	int pageSize = getpagesize();
	size_t pageAddr = (size_t)thunk & ~(pageSize - 1);
	int result = mprotect((void*)pageAddr, pageSize, PROT_READ | PROT_WRITE | PROT_EXEC);
	if (result != 0)
	{
		err::setLastSystemError();
		printf("mprotect failed: %s\n", err::getLastErrorDescription().sz());
		exit(-1);
	}
#endif

	thunk->m_code = g_thunkCodeTemplate;
	thunk->m_code.m_targetFunc1 = (uint64_t)targetFunc;
	thunk->m_code.m_targetFunc2 = (uint64_t)targetFunc;
	thunk->m_code.m_targetFunc3 = (uint64_t)targetFunc;
	thunk->m_code.m_hookRet = (uint64_t)((char*)thunk + sizeof(ThunkCode::m_hookRetOffset));
	thunk->m_code.m_hookEnterFunc = (uint64_t)hookEnter;
	thunk->m_code.m_hookLeaveFunc = (uint64_t)hookLeave;

#if (WIN32)
	thunk->m_code.m_hookExceptionFunc = (uint64_t)hookException;

	thunk->m_runtimeFunction.BeginAddress = 0;
	thunk->m_runtimeFunction.EndAddress = sizeof(ThunkCode);
	thunk->m_runtimeFunction.UnwindInfoAddress = (DWORD)((char*)&thunk->m_unwindInfo - (char*)thunk);

	thunk->m_unwindInfo.Version = 1;
	thunk->m_unwindInfo.Flags = UNW_FLAG_EHANDLER;
	thunk->m_unwindInfo.SizeOfProlog = 0;
	thunk->m_unwindInfo.FrameRegister = 0;
	thunk->m_unwindInfo.FrameOffset = 0;
	thunk->m_unwindInfo.CountOfCodes = 0;

	thunk->m_exceptionHandler = sizeof(ThunkCode::m_hookSehHandlerOffset);
	thunk->m_exceptionParam = targetFunc;

	uint64_t base = (uint64_t)thunk;
	RtlAddFunctionTable(&thunk->m_runtimeFunction, 1, base);
#endif

	return thunk;
}

//..............................................................................

// uses up all register arguments and spills to stack

typedef int FooFunc(int, double, int, double, int, double, int, double, int, double);

int bar(int a, double b, int c, double d, int e, double f, int g, double h, int i, double j)
{
	printf("bar(%d, %f, %d, %f, %d, %f, %d, %f, %d, %f)\n", a, b, c, d, e, f, g, h, i, j);

#if (_AXL_OS_WIN)
	*g_p = 10;
#endif

	return 456;
}

int foo(int a, double b, int c, double d, int e, double f, int g, double h, int i, double j)
{
	printf("foo(%d, %f, %d, %f, %d, %f, %d, %f, %d, %f)\n", a, b, c, d, e, f, g, h, i, j);
	return bar(a, b, c, d, e, f, g, h, i, j);
}

#if (_AXL_OS_WIN)
static CONTEXT g_context = { 0 }; // global so it doesn't affect function
#endif

int testSehFilter(EXCEPTION_POINTERS* exceptionPointers)
{
	printf("testSehFilter");
	return EXCEPTION_CONTINUE_SEARCH;
}

int test(int a, double b, int c, double d, int e, double f, int g, double h, int i, double j)
{
	printf("test(%d, %f, %d, %f, %d, %f, %d, %f, %d, %f)\n", a, b, c, d, e, f, g, h, i, j);

#if (_PRINT_UNWIND_INFO)
	g_context.ContextFlags = CONTEXT_CONTROL;
	RtlCaptureContext(&g_context);
	printUnwindInfo(g_context.Rip);
#endif

	int result = -1;

	g_p = (int*)::VirtualAlloc(
		NULL,
		4096,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READONLY
		);

	Thunk* thunk = createThunk((void*)foo);

	__try
	{
		result = ((FooFunc*)&thunk->m_code)(a, b, c, d, e, f, g, h, i, j);
		printf("jmpThunk -> %d\n", result);
	}
	__except(testSehFilter(GetExceptionInformation()))
	{
		printf("exception caught in test()\n");
	}

	return result;
}

//..............................................................................

int mainSehFilter(EXCEPTION_POINTERS* exceptionPointers)
{
	printf("mainSehFilter");
	return EXCEPTION_CONTINUE_SEARCH;
}

//..............................................................................

#endif

#define UNWIND_HISTORY_TABLE_NONE 0
#define UNWIND_HISTORY_TABLE_GLOBAL 1
#define UNWIND_HISTORY_TABLE_LOCAL 2

VOID
RtlpCopyContext (
    OUT PCONTEXT Destination,
    IN PCONTEXT Source
    )

/*++

Routine Description:

    This function copies the nonvolatile context required for exception
    dispatch and unwind from the specified source context record to the
    specified destination context record.

Arguments:

    Destination - Supplies a pointer to the destination context record.

    Source - Supplies a pointer to the source context record.

Return Value:

    None.

--*/

{

    //
    // Copy nonvolatile context required for exception dispatch and unwind.
    //

    Destination->Rip = Source->Rip;
    Destination->Rbx = Source->Rbx;
    Destination->Rsp = Source->Rsp;
    Destination->Rbp = Source->Rbp;
    Destination->Rsi = Source->Rsi;
    Destination->Rdi = Source->Rdi;
    Destination->R12 = Source->R12;
    Destination->R13 = Source->R13;
    Destination->R14 = Source->R14;
    Destination->R15 = Source->R15;
    Destination->Xmm6 = Source->Xmm6;
    Destination->Xmm7 = Source->Xmm7;
    Destination->Xmm8 = Source->Xmm8;
    Destination->Xmm9 = Source->Xmm9;
    Destination->Xmm10 = Source->Xmm10;
    Destination->Xmm11 = Source->Xmm11;
    Destination->Xmm12 = Source->Xmm12;
    Destination->Xmm13 = Source->Xmm13;
    Destination->Xmm14 = Source->Xmm14;
    Destination->Xmm15 = Source->Xmm15;
    Destination->SegCs = Source->SegCs;
    Destination->SegSs = Source->SegSs;
    Destination->MxCsr = Source->MxCsr;
    Destination->EFlags = Source->EFlags;

    return;
}

BOOLEAN
RtlpIsFrameInBounds (
    IN OUT PULONG64 LowLimit,
    IN ULONG64 StackFrame,
    IN OUT PULONG64 HighLimit
    )

/*++

Routine Description:

    This function checks whether the specified frame address is properly
    aligned and within the specified limits. In kernel mode an additional
    check is made if the frame is not within the specified limits since
    the kernel stack can be expanded. For this case the next entry in the
    expansion list, if any, is checked. If the frame is within the next
    expansion extent, then the extent values are stored in the low and
    high limit before returning to the caller.

    N.B. It is assumed that the supplied high limit is the stack base.

Arguments:

    LowLimit - Supplies a pointer to a variable that contains the current
        lower stack limit.

    Frame - Supplies the frame address to check.

    HighLimit - Supplies a pointer to a variable that contains the current
        high stack limit.

Return Value:

    If the specified stack frame is within limits, then a value of TRUE is
    returned as the function value. Otherwise, a value of FALSE is returned.

--*/

{
    if ((StackFrame & 0x7) != 0) {
        return FALSE;
    }

    if ((StackFrame < *LowLimit) ||
        (StackFrame >= *HighLimit)) {
		return FALSE;
    } else {
        return TRUE;
    }
}

typedef
VOID
RtlRaiseExceptionFunc(EXCEPTION_RECORD* ExceptionRecord);

RtlRaiseExceptionFunc* g_rtlRaiseException = NULL;

DECLSPEC_NOINLINE
VOID
RtlRaiseStatus (
    IN LONG Status
    )

/*++

Routine Description:

    This function raises an exception with the specified status value. The
    exception is marked as noncontinuable with no parameters.

    N.B. There is no return from this function.

Arguments:

    Status - Supplies the status value to be used as the exception code
        for the exception that is to be raised.

Return Value:

    None.

--*/

{
	printf("RtlRaiseStatus\n");

    CONTEXT ContextRecord;
    EXCEPTION_RECORD ExceptionRecord;

    //
    // Capture the current context and construct an exception record.
    //

    RtlCaptureContext(&ContextRecord);
    ExceptionRecord.ExceptionCode = Status;
    ExceptionRecord.ExceptionRecord = NULL;
    ExceptionRecord.NumberParameters = 0;
    ExceptionRecord.ExceptionFlags = EXCEPTION_NONCONTINUABLE;
    ExceptionRecord.ExceptionAddress = (PVOID)ContextRecord.Rip;

	g_rtlRaiseException(&ExceptionRecord);
}

typedef
void
WINAPI
GetCurrentThreadStackLimitsFunc(
	PULONG_PTR LowLimit,
	PULONG_PTR HighLimit
	);


GetCurrentThreadStackLimitsFunc* g_getCurrentThreadStackLimits = NULL;

typedef
EXCEPTION_DISPOSITION
RtlpExecuteHandlerForExceptionFunc (
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN PVOID EstablisherFrame,
	IN OUT PCONTEXT ContextRecord,
	IN OUT PVOID DispatcherContext
	);

RtlpExecuteHandlerForExceptionFunc* g_rtlpExecuteHandlerForException = NULL;

uchar_t g_rtlpExecuteHandlerForExceptionCode[0x13] =
{
	0x48, 0x83, 0xEC, 0x28,        // 00000000  sub     rsp, STACK_FRAME_SIZE
	0x4C, 0x89, 0x4C, 0x24, 0x20,  // 00000004  mov     [rsp + REG_ARG_HOME_SIZE], r9
	0x41, 0xFF, 0x51, 0x30,        // 00000009  call    [r9 + DISPATCH_CONTEXT_HANDLER]
	0x90,                          // 0000000D  nop
	0x48, 0x83, 0xC4, 0x28,        // 0000000E  add     rsp, STACK_FRAME_SIZE
	0xC3,                          // 00000012  ret
};

BOOLEAN
RtlDispatchException (
    IN PEXCEPTION_RECORD ExceptionRecord,
    IN PCONTEXT ContextRecord
    )

/*++

Routine Description:

    This function attempts to dispatch an exception to a frame based
    handler by searching backwards through the stack based call frames.
    The search begins with the frame specified in the context record and
    continues backward until either a handler is found that handles the
    exception, the stack is found to be invalid (i.e., out of limits or
    unaligned), or the end of the call hierarchy is reached.

    As each frame is encounter, the PC where control left the corresponding
    function is determined and used to lookup exception handler information
    in the runtime function table built by the linker. If the respective
    routine has an exception handler, then the handler is called. If the
    handler does not handle the exception, then the prologue of the routine
    is executed backwards to "unwind" the effect of the prologue and then
    the next frame is examined.

Arguments:

    ExceptionRecord - Supplies a pointer to an exception record.

    ContextRecord - Supplies a pointer to a context record.

Return Value:

    If the exception is handled by one of the frame based handlers, then
    a value of TRUE is returned. Otherwise a value of FALSE is returned.

--*/

{
    BOOLEAN Completion = FALSE;
    CONTEXT ContextRecord1;
    ULONG64 ControlPc;
    DISPATCHER_CONTEXT DispatcherContext;
    EXCEPTION_DISPOSITION Disposition;
    ULONG64 EstablisherFrame;
    ULONG ExceptionFlags;
    PEXCEPTION_ROUTINE ExceptionRoutine;
    PRUNTIME_FUNCTION FunctionEntry;
    PVOID HandlerData;
    ULONG64 HighLimit;
    PUNWIND_HISTORY_TABLE HistoryTable;
    ULONG64 ImageBase;
    ULONG64 LowLimit;
    ULONG64 NestedFrame;
    BOOLEAN Repeat;
    ULONG ScopeIndex;
    UNWIND_HISTORY_TABLE UnwindTable;
	SIZE_T FrameIndex = 0;

    //
    // Get current stack limits, copy the context record, get the initial
    // PC value, capture the exception flags, and set the nested exception
    // frame pointer.
    //

    g_getCurrentThreadStackLimits(&LowLimit, &HighLimit);



    RtlpCopyContext(&ContextRecord1, ContextRecord);
    ControlPc = (ULONG64)ExceptionRecord->ExceptionAddress;
    ExceptionFlags = ExceptionRecord->ExceptionFlags & EXCEPTION_NONCONTINUABLE;
    NestedFrame = 0;

    //
    // Initialize the unwind history table.
    //

    HistoryTable = &UnwindTable;
    HistoryTable->Count = 0;
    HistoryTable->Search = UNWIND_HISTORY_TABLE_NONE;
    HistoryTable->LowAddress = - 1;
    HistoryTable->HighAddress = 0;

    //
    // Start with the frame specified by the context record and search
    // backwards through the call frame hierarchy attempting to find an
    // exception handler that will handle the exception.
    //

    do {

        //
        // Lookup the function table entry using the point at which control
        // left the procedure.
        //

        FunctionEntry = RtlLookupFunctionEntry(ControlPc,
                                               &ImageBase,
                                               HistoryTable);

		printf("+RtlDispatchException(%d), FunctionEntry: %p\n", FrameIndex, FunctionEntry);

        //
        // If there is a function table entry for the routine, then virtually
        // unwind to the caller of the current routine to obtain the virtual
        // frame pointer of the establisher and check if there is an exception
        // handler for the frame.
        //

        if (FunctionEntry != NULL) {

			ExceptionRoutine = RtlVirtualUnwind(UNW_FLAG_EHANDLER,
                                                ImageBase,
                                                ControlPc,
                                                FunctionEntry,
                                                &ContextRecord1,
                                                &HandlerData,
                                                &EstablisherFrame,
                                                NULL);

            //
            // If the establisher frame pointer is not within the specified
            // stack limits or the established frame pointer is unaligned,
            // then set the stack invalid flag in the exception record and
            // return exception not handled. Otherwise, check if the current
            // routine has an exception handler.
            //

            if (RtlpIsFrameInBounds(&LowLimit, EstablisherFrame, &HighLimit) == FALSE) {
                ExceptionFlags |= EXCEPTION_STACK_INVALID;
                break;
            }

			if (ExceptionRoutine != NULL) { // && FrameIndex) { // skip the very first one (us)

                //
                // The frame has an exception handler.
                //
                // A linkage routine written in assembler is used to actually
                // call the actual exception handler. This is required by the
                // exception handler that is associated with the linkage
                // routine so it can have access to two sets of dispatcher
                // context when it is called.
                //
                // Call the language specific handler.
                //

                ScopeIndex = 0;
                do {

                    //
                    // Log the exception if exception logging is enabled.
                    //

                    ExceptionRecord->ExceptionFlags = ExceptionFlags;

                    //
                    // Clear repeat, set the dispatcher context, and call the
                    // exception handler.
                    //

                    Repeat = FALSE;
                    DispatcherContext.ControlPc = ControlPc;
                    DispatcherContext.ImageBase = ImageBase;
                    DispatcherContext.FunctionEntry = FunctionEntry;
                    DispatcherContext.EstablisherFrame = EstablisherFrame;
                    DispatcherContext.ContextRecord = &ContextRecord1;
                    DispatcherContext.LanguageHandler = ExceptionRoutine;
                    DispatcherContext.HandlerData = HandlerData;
                    DispatcherContext.HistoryTable = HistoryTable;
                    DispatcherContext.ScopeIndex = ScopeIndex;

					if (FrameIndex == 9)
						printf("tak-tak-tak\n");

                    Disposition = g_rtlpExecuteHandlerForException(
						ExceptionRecord,
                        (PVOID)EstablisherFrame,
                        ContextRecord,
                        &DispatcherContext);

                    //
                    // Propagate noncontinuable exception flag.
                    //

                    ExceptionFlags |=
                        (ExceptionRecord->ExceptionFlags & EXCEPTION_NONCONTINUABLE);

                    //
                    // If the current scan is within a nested context and the
                    // frame just examined is the end of the nested region,
                    // then clear the nested context frame and the nested
                    // exception flag in the exception flags.
                    //

                    if (NestedFrame == EstablisherFrame) {
                        ExceptionFlags &= (~EXCEPTION_NESTED_CALL);
                        NestedFrame = 0;
                    }

                    //
                    // Case on the handler disposition.
                    //

                    switch (Disposition) {

                        //
                        // The disposition is to continue execution.
                        //
                        // If the exception is not continuable, then raise
                        // the exception STATUS_NONCONTINUABLE_EXCEPTION.
                        // Otherwise return exception handled.
                        //

                    case ExceptionContinueExecution :
                        if ((ExceptionFlags & EXCEPTION_NONCONTINUABLE) != 0) {
                            RtlRaiseStatus(STATUS_NONCONTINUABLE_EXCEPTION);

                        } else {
                            Completion = TRUE;
                            goto DispatchExit;
                        }

                        //
                        // The disposition is to continue the search.
                        //
                        // Get next frame address and continue the search.
                        //

                    case ExceptionContinueSearch :
                        break;

                        //
                        // The disposition is nested exception.
                        //
                        // Set the nested context frame to the establisher frame
                        // address and set the nested exception flag in the
                        // exception flags.
                        //

                    case ExceptionNestedException :
                        ExceptionFlags |= EXCEPTION_NESTED_CALL;
                        if (DispatcherContext.EstablisherFrame > NestedFrame) {
                            NestedFrame = DispatcherContext.EstablisherFrame;
                        }

                        break;

                        //
                        // The dispostion is collided unwind.
                        //
                        // A collided unwind occurs when an exception dispatch
                        // encounters a previous call to an unwind handler. In
                        // this case the previous unwound frames must be skipped.
                        //

                    case ExceptionCollidedUnwind:
                        ControlPc = DispatcherContext.ControlPc;
                        ImageBase = DispatcherContext.ImageBase;
                        FunctionEntry = DispatcherContext.FunctionEntry;
                        EstablisherFrame = DispatcherContext.EstablisherFrame;
                        RtlpCopyContext(&ContextRecord1,
                                        DispatcherContext.ContextRecord);

                        ContextRecord1.Rip = ControlPc;
                        ExceptionRoutine = DispatcherContext.LanguageHandler;
                        HandlerData = DispatcherContext.HandlerData;
                        HistoryTable = DispatcherContext.HistoryTable;
                        ScopeIndex = DispatcherContext.ScopeIndex;
                        Repeat = TRUE;
                        break;

                        //
                        // All other disposition values are invalid.
                        //
                        // Raise invalid disposition exception.
                        //

                    default :
                        RtlRaiseStatus(STATUS_INVALID_DISPOSITION);
                    }

                } while (Repeat != FALSE);
            }

        } else {

            //
            // If the old control PC is the same as the return address,
            // then no progress is being made and the function tables are
            // most likely malformed.
            //

            if (ControlPc == *(PULONG64)(ContextRecord1.Rsp)) {
                break;
            }

            //
            // Set the point where control left the current function by
            // obtaining the return address from the top of the stack.
            //

            ContextRecord1.Rip = *(PULONG64)(ContextRecord1.Rsp);
            ContextRecord1.Rsp += 8;
        }

        //
        // Set point at which control left the previous routine.
        //

        ControlPc = ContextRecord1.Rip;
		FrameIndex++;
	} while (RtlpIsFrameInBounds(&LowLimit, (ULONG64)ContextRecord1.Rsp, &HighLimit) == TRUE);

    //
    // Set final exception flags and return exception not handled.
    //

    ExceptionRecord->ExceptionFlags = ExceptionFlags;

    //
    // Call vectored continue handlers.
    //

DispatchExit:

    return Completion;
}

//..............................................................................

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

			ASSERT(false);
			break;

		case ExceptionCollidedUnwind:
			// an edge-case, really, so not critical to process. maybe later... for now -- bail.

		default:
			// bail -- restore the original return-ip (thus eliminating this handler) and retry exception
			return false;
		}
	}

	return false;
}

int seh_baz_filter(EXCEPTION_POINTERS* exceptionPointers)
{
	printf("seh_baz_filter\n");

	bool result = dispatchException(
		exceptionPointers->ExceptionRecord,
		exceptionPointers->ContextRecord,
		exceptionPointers->ContextRecord->Rip,
		exceptionPointers->ContextRecord->Rsp
		);

	printf("dispatchException -> %d\n", result);
	return result ? EXCEPTION_CONTINUE_EXECUTION : EXCEPTION_CONTINUE_SEARCH;
}

int* g_p = NULL;

void seh_baz()
{
	__try
	{
		printf("seh_baz\n");
		*g_p = 0;
	}
	__except(seh_baz_filter(GetExceptionInformation()))
	{
		printf("seh_baz::__except\n");
	}
}

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

int seh_bar_filter(EXCEPTION_POINTERS* exceptionPointers)
{
	printf("seh_bar_filter\n");
	return EXCEPTION_CONTINUE_SEARCH;
}

void seh_bar()
{
	__try
	{
		printf("seh_bar\n");
		seh_baz();
	}
	__except(seh_bar_filter(GetExceptionInformation()))
	{
		printf("seh_bar::__except\n");
	}
}

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

int seh_foo_filter(EXCEPTION_POINTERS* exceptionPointers)
{
	printf("seh_foo_filter\n");
	return EXCEPTION_CONTINUE_SEARCH;
//	return EXCEPTION_EXECUTE_HANDLER;
}

void seh_foo()
{
	__try
	{
		printf("seh_foo\n");
		seh_bar();
	}
	__except(seh_foo_filter(GetExceptionInformation()))
	{
		printf("seh_foo::__except\n");
	}
}

//..............................................................................

int seh_main_filter(EXCEPTION_POINTERS* exceptionPointers)
{
	printf("seh_main_filter\n");

	DWORD oldProtect;
	::VirtualProtect(g_p, 4096, PAGE_READWRITE, &oldProtect);

	return EXCEPTION_CONTINUE_EXECUTION;
}

int main()
{
#if (0)

#if (_AXL_OS_WIN)
	BOOL result = SymInitialize(INVALID_HANDLE_VALUE, NULL, true);

	__try
	{
#if (_PRINT_UNWIND_INFO)
		g_context.ContextFlags = CONTEXT_CONTROL;
		RtlCaptureContext(&g_context);
		printUnwindInfo(g_context.Rip);
#endif
		test(10, 20, 30, 40, 50, 60, 70, 80, 90, 100);
	}
	__except(mainSehFilter(GetExceptionInformation()))
	{
		printf("exception caught in main()\n");
	}
#else
	setvbuf(stdout, NULL, _IOLBF, 1024);

	test(10, 20, 30, 40, 50, 60, 70, 80, 90, 100);
#endif

#endif

	HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
	HMODULE kernel32 = ::GetModuleHandleW(L"kernel32.dll");

	g_rtlRaiseException = (RtlRaiseExceptionFunc*)GetProcAddress(ntdll, "RtlRaiseException");
	g_getCurrentThreadStackLimits = (GetCurrentThreadStackLimitsFunc*)GetProcAddress(kernel32, "GetCurrentThreadStackLimits");

	g_rtlpExecuteHandlerForException = (RtlpExecuteHandlerForExceptionFunc*)::VirtualAlloc(
		NULL,
		sizeof(g_rtlpExecuteHandlerForExceptionCode),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
		);

	memcpy(
		g_rtlpExecuteHandlerForException,
		g_rtlpExecuteHandlerForExceptionCode,
		sizeof(g_rtlpExecuteHandlerForExceptionCode)
		);

	g_p = (int*)::VirtualAlloc(
		NULL,
		4096,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READONLY
		);

	__try
	{
		printf("main\n");
		seh_foo();
	}
	__except(seh_main_filter(GetExceptionInformation()))
	{
		printf("main::__except\n");
	}

	return 0;
}

//..............................................................................
