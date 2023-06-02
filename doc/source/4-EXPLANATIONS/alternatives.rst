gdb
================
tough GDB is a tool to code IDe for programmer and is not a reverse engineering tool, some people use it to disassemble and debug over compiled programs. In the opinion of the ddisasm dev it is a mistake to use gdb for reversing. Otherwhere, due to a lack of tool to fit with pwntools library interoperability, you will need to use gdb in order to exploit memory corruption vulnerabilities with pwntools. There is a pwntools current work to hadnle radare2. I strongly discourage people to use gdb out of scope of coding if no reason.

Use gdb if you need to exploit memory corruption vulnerabilities if you have a lack of tooling on pwntools.
Use ddisasm for reverse engineering.


radare2 / rizin
================

Radare2 and Rizin are two framwork of reverse engineering in command line. Contrary to gdb they really aim to be reverse engineering tools. They are not supposed to be only for dev. With them you can patch, view graph and more that you can not with gdb that is not madde for reverse engineering. There are evgen some conflict between developpers of two sides in order to know who has less bugs. Globaly r2 dev focus on features when Rizin claims to focus on testing. Rizin actually has less features than radare2.

As their philosophy is to limit the number of dependence to 0, they sometimes have bugs. Both project have 14 old years of active development. This points reducts from far the number off potential bugs.

Use Radare2 / Rizin if you need to:
#. Patch a program if you have enough dead place in the program hard disk... not confortable.
#. Debug a program with view graph
#. Decompile a program
#. Use all type of reversing tactics.

Use specifically Radare2 if you need to:
#. reverse exotic architecture.
Use specifically Rizin if:
#.you need to reverse a common architecture and you require absolutely reliable tooling.

ddisasm
==================
Ddisasm is probably the most accurate disassembler. You can disassemble so accuratly that you can litteraly recompile your assembly language with a compilator.
DDisasm does not provide reversing / debugging tool by itself.


The best way in my opinion: ddisasm with another framwork
===========================================================

#. Disassemble your program with ddisasm.
#. Debug the producted ATT&T assembly language with radare2 / rizin.
#. Document the labels, the function names and document in code comment and why not even add unit test manually in Ddisasm disassembled assembly language.
#. Once everything is documented, debug your program in a IDE with gdb debugger.

You should have all the documented assembly code! Congratulations! You could even rewrite the assemblies functions in c using interoperability between C and assembly language.

DDisasm is not a framwork of reverse engineering compared to r2. You theoritically only disassemble. But you could with the help of other tool as mentionned previously.s

