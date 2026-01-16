SECTIONS
{
    /* place message at fixed address */
    . = 0x712300;
    .data : {
        *(.data*)
    }
}
INSERT AFTER .rodata;
