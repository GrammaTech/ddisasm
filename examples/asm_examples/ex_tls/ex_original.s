
    .align 16
    .globl  main
    .type   main, @function
main:
.LFB6:
    pushq   %rbp
    movq    %rsp, %rbp
    call    bar@PLT
    movl    $0, %eax
    popq    %rbp
    ret

.LFE6:
    .size    main, .-main
