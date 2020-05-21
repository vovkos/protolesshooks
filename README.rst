Prototypeless Hooks
===================

.. image:: https://travis-ci.org/vovkos/protolesshooks.svg?branch=master
	:target: https://travis-ci.org/vovkos/protolesshooks
.. image:: https://ci.appveyor.com/api/projects/status/enh19e87fmxhqurc?svg=true
	:target: https://ci.appveyor.com/project/vovkos/protolesshooks

Abstract
--------

The ``protolesshooks`` library provides a **hooking engine** that works **without information on target functions prototypes**.

This code is intended for use in the upcoming **API Spy** plugin for `IO Ninja <https://ioninja.com>`__; API Spy is going to be an advanced cross-platform alternative for ``ltrace``.

Overview
--------

The idea of **API hooking** is to intercept calls to system or 3rd-party libraries and redirect those through your *spy functions*, also known as *hooks*. Hooking is often required in reverse-engineering and many other non-trivial debugging scenarios. Depending on the chosen hooking method, with hooks you can:

1. Display API function names called by the process;
2. Measure the time of each call;
3. Build a call-graph;
4. Inspect/modify function call arguments;
5. Inspect/modify return values;
6. Block the target function completely.

Most hooking-related libraries, frameworks, and articles focus on *injection techniques*, i.e., the details of making your hook getting called every time before the original function. Once this task is accomplished, the problem is deemed to be solved -- your hook can now *proxy-call* the original function, pass its return value back to the caller, and perform logging/argument/retval modification as necessary.

The problem here, however, is that you **can't proxy-call without target function prototypes**! Yes, it's easy to jump directly to the original function (thus getting the capability (1) of the list above). But for (2), (3), and (5) your hook needs to *regain control after return* from the target function -- which is trivial with the knowledge of target function prototypes, and quite challenging without.

	Not to state the obvious, but to encode prototypes for *all* the library calls in a process is nearly impossible -- there could be hundreds of different API calls, and many of those may be undocumented.

The ``protolesshooks`` library provides return-hijacking thunks that work *without* the knowledge of target functions prototypes. This makes it possible, for example, to enumerare and intercept *all shared libraries* in a process, gain a birds-eye overview of the API call-graph, then gradually add prototype information for parameter/retval decoding as necessary.

	A point worth mentioning is that with the presented method, the prototype information can be incomplete. For instance, we may have some clues about the first two parameters of a particular function, but no idea about the rest. With the traditional hooking (when your hook is inserted into the call chain), it's just not going to work -- you need *exact information* about the expected stack frame! With ``protolesshooks`` it's absolutely fine.

Features
--------

* Works without (or with partial) information about target function prototypes;
* Function entry hooks;
* Function exit hooks;
* SEH-exception hooks (Windows x64 only);
* Arguments can be modified before jumping to the target function;
* Retvals can be modified before returning to the caller;
* The target function can be blocked if necessary;
* Thunks can be used with trampoline-based hooking engines, too.

Supported calling conventions:

* Microsoft x64 (MSC);
* SystemV AMD64 (GCC/Clang);
* x86 cdecl (MSC, GCC/Clang);
* x86 stdcall (MSC, GCC/Clang);
* x86 __thiscall (MSC);
* x86 __fastcall (MSC);
* x86 __attribute__((regparm(n)) (GCC/Clang).

Built-in enumerators for import tables:

* PE (Windows)
* ELF (Linux)
* Mach-O (macOS)

SEH x64 Note
~~~~~~~~~~~~

On Windows x64, thunks properly dispatch exceptions to lower SEH handlers without losing the hook after the first exception. This is important because multiple exceptions can occur without unwinding (if one of the SEH filters returns ``EXCEPTION_CONTINUE_EXECUTION``), for example:

.. code-block:: cpp

	void foo()
	{
		// recoverable exception happens here...
		...
		// now unrecoverable exception happens here...
	}

	int barFilter(EXCEPTION_POINTERS* exception)
	{
		if (/* can recover? */)
		{
			// recover, e.g. commit/protect the faulting page
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		return EXCEPTION_EXECUTE_HANDLER;
	}

	void bar()
	{
		__try
		{
			foo();
		}
		__except (barFilter(GetExceptionInformation()))
		{
			// unrecoverable exception is caught here
		}
	}

Samples
-------

* `sample_00_trivial <https://github.com/vovkos/protolesshooks/blob/master/samples/sample_00_trivial.cpp>`__

	The hello-world sample. Allocates a basic enter/leave hook for a void function with no arguments; then calls it directly.

* `sample_01_params <https://github.com/vovkos/protolesshooks/blob/master/samples/sample_01_params.cpp>`__

	Demonstrates how to decode register and stack arguments and return values.

* `sample_02_enum <https://github.com/vovkos/protolesshooks/blob/master/samples/sample_02_enum.cpp>`__

	Demonstrates how to enumerate all loaded modules and imports for each module.

* `sample_03_global <https://github.com/vovkos/protolesshooks/blob/master/samples/sample_03_global.cpp>`__

	Demonstrates the global interception of all imports in all loaded modules.

* `sample_04_modify <https://github.com/vovkos/protolesshooks/blob/master/samples/sample_04_modify.cpp>`__

	Demonstrates how to modify arguments and return.

* `sample_05_block <https://github.com/vovkos/protolesshooks/blob/master/samples/sample_05_block.cpp>`__

	Demonstrates how to pass-through, proxy-call, or completely block the target function.
