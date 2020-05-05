Prototypeless Hooks
===================

Abstract
--------

The general idea of **API hooking** is to intercept calls which a process is making to system or 3rd-party libraries and make these calls go through your *spy* functions, also known as *hooks*. Hooking can be essential in reverse-engineering and many other non-trivial debugging scenarios. There exist a wide range of different hooking techniques; depending on the method, hooks allow you to:

1. Display API function names called by the process;
2. Measure the time of each call;
3. Build a call-graph;
4. Inspect/modify function call arguments;
5. Inspect/modify return values.

However, most hooking-related libraries, frameworks, and articles concentrate on *injection* techniques, i.e. how to modify the process' memory in order to make your hook called every time the process attempts to access the original function. Once it's accomplished, it is assumed that the problem is solved -- your hook can now call the original function and then pass its return value back to the caller, performing the necessary logging or argument/retval modification in the process.

The principal problem here is that without the knowledge of *target function prototypes* you can't do this simple proxy-calling! It's still relatively easy to log function arguments and then just jump to the original function; it allows for making a planar list of API calls, i.e. the capability (1) of the list above. But for (2), (3), and (5) your hook needs to *gain control back after return* from the target function -- trivial with the knowledge of target function prototypes, challenging without. And encoding prototypes for *all* the library calls in a process is nearly impossible -- there may be hundreds of different API calls, some of which may be undocumented at all.

This library provides a non-intrusive (non-trampoline) hooking technique capable of return hijacking *without* the knowledge of target functions prototypes.

Features
--------

* Return address hijacking without prototypes
* Detects exits via Windows SEH x64
* Supported calling conventions:
	- Microsoft x64
	- SystemV AMD64 (GCC, Clang)
	- x86 cdecl & stdcall (MSVC, GCC, Clang)

With ``protolesshooks`` it is possible, for example, to enumerare and intercept all shared libraries in a process, gain an overview, then gradually add prototype information for parameter/retval decoding where necessary.

	* A point worth mentioning is that with this method, the prototype information can be incomplete. For instance, we may have some clues about the first two parameters for a particular function, but no idea about the rest. With the traditional hooking (when your hook is inserted into the call chain), it's just not going to work unless you have *exact* information about the expected stack frame. With ``protolesshooks`` it's absolutely fine.
