#define _GNU_SOURCE
#include <link.h>
#include <stdio.h>

/* Defined by the linker at the start of .dynamic. The rewritten binary gets
   a new .dynamic from the linker, so references must stay symbolic. */
extern ElfW(Dyn) _DYNAMIC[] __attribute__((visibility("hidden")));

/* Taking the address is a pc-relative LEA in PIE builds and an absolute
   immediate in non-PIE builds. */
__attribute__((noinline)) const ElfW(Dyn) * dynamic_start(void)
{
    return _DYNAMIC;
}

/* A load from _DYNAMIC. */
__attribute__((noinline)) ElfW(Sxword) first_tag(void)
{
    return _DYNAMIC[0].d_tag;
}

#ifdef __PIE__
/* A pointer stored in data: a RELATIVE relocation in PIE builds. */
const void *volatile dyn_ref = _DYNAMIC;
#endif

/* The first object reported is the executable itself. */
static int find_dynamic(struct dl_phdr_info *info, size_t size, void *data)
{
    const ElfW(Dyn) **out = data;
    (void)size;
    for(int i = 0; i < info->dlpi_phnum; i++)
    {
        if(info->dlpi_phdr[i].p_type == PT_DYNAMIC)
        {
            *out = (const ElfW(Dyn) *)(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
        }
    }
    return 1;
}

int main(void)
{
    const ElfW(Dyn) *expected = NULL;
    dl_iterate_phdr(find_dynamic, &expected);

    const ElfW(Dyn) *d = dynamic_start();
    int address_ok = expected != NULL && d == expected;
    int load_ok = expected != NULL && first_tag() == expected[0].d_tag;
#ifdef __PIE__
    int data_ok = dyn_ref == (const void *)expected;
#else
    int data_ok = 1;
#endif

    printf("address %s, load %s, data %s\n", address_ok ? "ok" : "BAD", load_ok ? "ok" : "BAD",
           data_ok ? "ok" : "BAD");
    return !(address_ok && load_ok && data_ok);
}
