Prototypeless Hooks
===================

.. image:: https://travis-ci.org/vovkos/protolesshooks.svg?branch=master
	:target: https://travis-ci.org/vovkos/protolesshooks
.. image:: https://ci.appveyor.com/api/projects/status/enh19e87fmxhqurc?svg=true
	:target: https://ci.appveyor.com/project/vovkos/protolesshooks

Abstract
--------

The ``protolesshooks`` library provides a non-intrusive (non-trampoline) thunking technique capable of return address hijacking *without* the knowledge of target functions prototypes.

This code is intended for use in the upcoming **API Spy** plugin for [IO Ninja](https://ioninja.com). API Spy is going to be an advanced cross-platform alternative for ``ltrace``.

Overview
--------

The general idea of **API hooking** is to intercept calls to system or 3rd-party libraries and redirect those calls through your *spy* functions, also known as *hooks*. Hooking is essential in reverse-engineering and many other non-trivial debugging scenarios. Depending on the chosen hooking method, hooks may allow you to:

1. Display API function names called by the process;
2. Measure the time of each call;
3. Build a call-graph;
4. Inspect/modify function call arguments;
5. Inspect/modify return values.

Most hooking-related libraries, frameworks, and articles focus on *injection techniques*, i.e., the details of modifying the process' memory in order to make your hook called every time the process invokes the original function. Once this task is accomplished, the problem is deemed to be solved -- your hook can now proxy-call the original function, pass its return value back to the caller, and perform logging/argument/retval modification as necessary.

The problem here, however, is that without the full knowledge of *target function prototypes* you can't proxy-call! It's easy to jump directly to the original function, yes -- and it allows creating a planar list of API calls (i.e. the capability (1) of the list above). But for (2), (3), and (5) your hook needs to *gain control back after return* from the target function -- which is trivial with the knowledge of target function prototypes, and quite challenging without. Not to state the obvious, but to encode prototypes for *all* the library calls in a process is nearly impossible -- there could be hundreds of different API calls, and some of those may be undocumented.

The ``protolesshooks`` library provides return-hijacking thunks which work *without* the knowledge of target functions prototypes. This makes it possible, for example, to enumerare and intercept *all shared libraries* in a process, gain a bird's-eye overview of the API call-graph, then gradually add prototype information for parameter/retval decoding as necessary.

	A point worth mentioning is that with the presented method, the prototype information can be incomplete. For instance, we may have some clues about the first two parameters of a particular function, but no idea about the rest. With the traditional hooking (when your hook is inserted into the call chain), it's just not going to work -- you need *exact information* about the expected stack frame! With ``protolesshooks`` it's absolutely fine.

Features
--------

* Function entry hook;
* Function exit hook;
* SEH exit hook (Windows x64 only).

Supported calling conventions:

* Microsoft x64 (MSVC);
* SystemV AMD64 (GCC/Clang);
* x86 cdecl & stdcall (MSVC, GCC/Clang).

On Windows x64 thunks properly dispatch exceptions to lower SEH handlers, without losing the hook after the first exception. This is important, because multiple exceptions can occur without unwinding (if one of the SEH filters returns ``EXCEPTION_CONTINUE_EXECUTION``), for example:

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

