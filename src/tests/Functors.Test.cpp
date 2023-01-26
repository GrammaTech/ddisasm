#include <gtest/gtest.h>

#include <fstream>
#include <gtirb/gtirb.hpp>

#include "../Functors.h"

TEST(Thumb32BranchOffsetTest, read_branch_offset)
{
    // 00000030 <main>:
    //  30:   b580            push    {r7, lr}
    //  32:   af00            add     r7, sp, #0
    //  34:   2114            movs    r1, #20
    //  36:   200a            movs    r0, #10
    //  38:   f7ff fffe       bl      0 <fun>
    //        ____ ____
    //         │    └── lower instruction
    //         └── upper instruction
    //
    EXPECT_EQ(functor_thumb32_branch_offset(0xfffef7ff), -4);
}
