#include <elf.h>
#include <link.h>
#include <stdio.h>

#if defined(__x86_64__)
#define EXPECTED_MACHINE EM_X86_64
#else
#define EXPECTED_MACHINE EM_386
#endif

/* Defined by the linker: the ELF header, mapped at the start of the image. */
extern const ElfW(Ehdr) __ehdr_start __attribute__((visibility("hidden")));

/* Taking the address is a pc-relative LEA in PIE builds and an absolute
   immediate (mov $__ehdr_start) in non-PIE builds. */
__attribute__((noinline)) const void *image_base(void)
{
    return &__ehdr_start;
}

int main(void)
{
    /* The header start and the header fields fail in different ways, so
       report them separately. */
    const unsigned char *p = image_base();
    int base_ok = p[0] == 0x7f && p[1] == 'E' && p[2] == 'L' && p[3] == 'F';

    /* Direct field accesses: pc-relative loads at small offsets into the
       header. */
    int fields_ok = __ehdr_start.e_ehsize == sizeof(ElfW(Ehdr))
                    && __ehdr_start.e_phentsize == sizeof(ElfW(Phdr))
                    && __ehdr_start.e_machine == EXPECTED_MACHINE;

    /* Printed rather than asserted, so the same source works for PIE and
       non-PIE builds */
    const char *type = __ehdr_start.e_type == ET_DYN    ? "DYN"
                       : __ehdr_start.e_type == ET_EXEC ? "EXEC"
                                                        : "other";

    printf("address %s, fields %s, type %s\n", base_ok ? "ok" : "BAD", fields_ok ? "ok" : "BAD",
           type);
    return !(base_ok && fields_ok);
}
