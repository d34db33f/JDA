This is JDA, a cross-platform disassembler -
short for Javascript Disasembler.

JDA can run in all modern browsers, but it requires a fairly huge
amount of RAM (on Chrome it may easily eat a couple hundred MB for
a 7KB executable).

JDA requires a well-formed binary, so it will likely fail to dissect
malware (but I haven't tried, either).

Currently JDA supports only 32-bit x86 Windows PE/COFF image files;
support is planned for DLL/SYS PE/COFF images and ELF executables and
libraries.

Instruction set for disassembly is for now limited to Intel 486+FPU,
but implementing extended ISAs or entirely new architectures should not
be a big problem.

JDA itself is published under the terms and conditions of the GPL2.0;
the included 3rd party JS libraries (jquery, jquery-binarytransport,
jquery-scrollto, keypress and w2ui) are distributed with their own
respective licenses.

== Motivation ==
There's not really much competition to IDA, the obvious leader.

I won't cover the commercial space; in the open-source world there's a
variety of disassemblers, but I could not find any interactive one that
comes close to the functionality of IDA Pro or at least PE Explorer.

I want to change this with JDA, a free and open-source program.

Either I will write my own disassembly engine or try to integrate the
Capstone engine project, but I'm not sure yet on how to proceed.

== Design goals ==
IDA has one very big problem: it "loses" information in the sense that
data present in the image file does not end up in the disassembly view
or even the subviews - e.g. "gaps" between sections, the MZ header
or the DOS stub.

The information in the "ASM View" window should be, given enough time,
sufficient to manually reproduce a byte-equal binary image.

Furthermore, neither IDA nor PE Explorer (or, for that matter, any
disassembler engine or environment except ODA) seem to support real
time collaboration between different people or not fucking up when used
with services like Dropbox.

UI design is intended to be close to IDA, including the hotkeys, because
it's easy to understand and due to the wide usage of IDA Free, IDA Pro
cracked and bought IDA Pro, many people are used to it.

In case I manage to get it running, there will be a "Pro" add-on which
allows the user to edit a binary - e.g. insert, remove or edit an
instruction and JDA will automatically recalculate offsets and xrefs
to produce a fully working and valid binary file.

I will not make any attempt at copy protection or whatever, it's wasted
time that can be used to improve JDA. I trust upon every user of JDA
and JDA Pro to behave like a normal human being.

== WinBro ==
Ah well, the maybe ugliest part of the program. WinBro is aimed to be a
merge of jslinux (javascript x86 emulator written by Fabrice Bellard),
WINE and JDA. In short, it will execute x86 code inside a JS CPU and
trap on call/jmp instructions to system library code (e.g. kernel32,
user32, ddraw and friends) to allow running programs inside a faked
"Windows" environment.

In contrast to live-system debugging of a binary, this has the advantage
of being truly undetectable to malware - the usual "debugger detection"
tricks like using tick counts or checksums to warn against JMP redirection
simply will not work as they can be emulated or aren't needed in this
environment.

== How can you help/contribute? ==
If you see a missing feature or a bug, look in the Github issue tracker.

If it's not mentioned there, please open a report, and if you want you
can already file a pull request if it's a simple bugfix - but please
don't start implementing huge new features or entire rewrites before
announcing your intent.

== Who's behind JDA? ==
I value my anonymity. The only public information available about me is
that I'm based in Germany and prefer to stay below the radar of 4chan,
cops and other nuisances. Please respect this.
