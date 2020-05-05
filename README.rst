Protolesshooks
==============

Abstract
--------

*Hooking* is essential in reverse-engineering and other non-trivial debugging scenarios. The basic idea is to intercept calls which the process under investigation is making to system or 3rd-party libraries with your *hooks*. There are different hooking techniques with different capabilities; depending on the method, hooks make it possible to:

	1. Display API function names called by the process;
	2. Measure the time of each call;
	3. Build a call-graph (when libraries call other libraries);
	4. Inspect/modify function call arguments;
	5. Inspect/modify return values.

The principal problem here is that without knowledge of the *target function prototype* you normally can only do the first one (1) -- for (2), (3), and (5) your hook needs to gain control back after return from the target function -- which, without the prototype information is hard to do. On the other hand, providing prototypes for *all* the library calls in a process is nearly impossible -- there may be hundreds or even thousands of different API calls, some of which may be undocumented.

This library provides a non-intrusive (non-trampoline) hooking engine capable of return hijacking *without* knowledge of the target functions prototypes.

Features
--------

	* Return address hijacking without prototypes
	* Detects exits via Windows SEH x64
	* Supported calling conventions:
		- Microsoft x64
		- SystemV AMD64 (GCC, Clang)
		- x86 cdecl & stdcall (MSVC, GCC, Clang)

All this makes it possible to enumerare and intercept all shared libraries in a process, gain an overview, then gradually add prototype information where necessary.

* A point worth mentioning is that with this method, the prototype information can be incomplete. For instance, we may have some clues about the first two parameters for a particular function, but no idea about the rest. With traditional hooking (when your hook is inserted into the call chain), it's just not going to work unless you have *exact* information about the expected stack frame. With ``protolesshooks`` -- no problem.
