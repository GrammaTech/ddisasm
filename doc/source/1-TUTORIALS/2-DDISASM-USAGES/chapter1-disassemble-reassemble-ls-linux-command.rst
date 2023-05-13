Chapter 1 disassemble and reassemble ls Linux command
=====================================================


Introduction
------------

We are going to disassemble the ls comand program on Linux. We will work on an x64 linux elf binary.

chapter 1: disassemble
-----------------------

cp "$(which ls)" new-ls
ddisasm ./new-ls --asm ls.s


chapter 1: reassemble
-----------------------

Reverse engineering the ls libraries.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In order to tell to the compiler (such as gcc) what libraries to use to recompile the program, we will do some reverse engineeing to list the libraries.


readelf --dynamic ./new-ls
Dynamic section at offset 0x21a58 contains 28 entries:
  Tag        Type                         Name/Value
 0x0000000000000001 (NEEDED)             Shared library: [libselinux.so.1]
 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
 
 Lets' focus on `Shared library: [libselinux.so.1]`. We now know that the program ls uses the library selinux. Let's install it.
 
 ```bash
 sudo apt install selinux-utils -y libselinux1-dev ;
 ```
 
Compile back!
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

gcc -nostartfiles ls.s  -o ls-out -l selinux


run!
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

./ls-out
myfile hey.png hello.out


Congratulation!

