import platform
import unittest

import gtirb

import snippets


class DataAccessTests(unittest.TestCase):
    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_x86_simple(self):
        module = snippets.asm_to_gtirb(
            """
            .access:
            movl .data0(%rip), %eax
            jmp .end
            .data0:
                .long 0
            .end:
            """
        )

        accesses = snippets.parse_souffle_output(
            module, "arch.simple_data_load"
        )
        self.assertIn(
            (
                next(module.symbols_named(".access")).referent.address,
                next(module.symbols_named(".data0")).referent.address,
                4,
            ),
            accesses,
        )

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_x86_composite(self):
        module = snippets.asm_to_gtirb(
            """
            .ref:
            leaq .data0(%rip), %rax
            .load:
            mov (.data1 - .data0)(%rax), %eax
            jmp .end
            .data0:
                .long 0
            .data1:
                .long 0
            .end:
            """
        )
        accesses = snippets.parse_souffle_output(
            module, "composite_data_access"
        )
        self.assertIn(
            (
                next(module.symbols_named(".ref")).referent.address,
                next(module.symbols_named(".load")).referent.address,
                next(module.symbols_named(".data1")).referent.address,
                4,
            ),
            accesses,
        )

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_arm_simple(self):
        module = snippets.asm_to_gtirb(
            """
            .access:
            ldr r0, .data0
            .data0:
                .long 0
            .end:
            """,
            arch=gtirb.Module.ISA.ARM,
        )

        accesses = snippets.parse_souffle_output(
            module, "arch.simple_data_load"
        )
        self.assertIn(
            (
                next(module.symbols_named(".access")).referent.address,
                next(module.symbols_named(".data0")).referent.address,
                4,
            ),
            accesses,
        )

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_arm_composite_ldr(self):
        module = snippets.asm_to_gtirb(
            """
            .ref:
            adr r0, .data0
            .load:
            ldr r0, [r0, #.data1-.data0]
            .data0:
                .long 0
            .data1:
                .long 0
            .end:
            """,
            arch=gtirb.Module.ISA.ARM,
        )

        accesses = snippets.parse_souffle_output(
            module, "composite_data_access"
        )
        self.assertIn(
            (
                next(module.symbols_named(".ref")).referent.address,
                next(module.symbols_named(".load")).referent.address,
                next(module.symbols_named(".data1")).referent.address,
                4,
            ),
            accesses,
        )

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_arm_composite_ldm(self):
        module = snippets.asm_to_gtirb(
            """
            .ref:
            adr r0, .data0
            .load:
            ldm r0, {r0, r1, r2}
            .data0:
                .long 0
                .long 1
                .long 2
            .end:
            """,
            arch=gtirb.Module.ISA.ARM,
        )

        accesses = snippets.parse_souffle_output(
            module, "composite_data_access"
        )
        self.assertIn(
            (
                next(module.symbols_named(".ref")).referent.address,
                next(module.symbols_named(".load")).referent.address,
                next(module.symbols_named(".data0")).referent.address,
                12,
            ),
            accesses,
        )

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_arm_composite_vld(self):
        module = snippets.asm_to_gtirb(
            """
            .ref:
            adr r0, .data0
            .load:
            vld1.8 {d0}, [r0]
            b .end
            .data0:
                .byte 0
            .align 2
            .end:
            """,
            arch=gtirb.Module.ISA.ARM,
        )

        accesses = snippets.parse_souffle_output(
            module, "composite_data_access"
        )
        self.assertIn(
            (
                next(module.symbols_named(".ref")).referent.address,
                next(module.symbols_named(".load")).referent.address,
                next(module.symbols_named(".data0")).referent.address,
                8,
            ),
            accesses,
        )
