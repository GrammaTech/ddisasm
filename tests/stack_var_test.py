import platform
import typing
import unittest

import gtirb

import snippets


def in_bounds(bounds: typing.Tuple[int, int], val: int):
    """
    Return if a value is within a range
    """
    return val >= bounds[0] and val < bounds[1]


stack_var_type = typing.Tuple[str, int]


def count_stack_def_use_in_snippet(
    module: gtirb.Module,
    stack_var_pair: typing.Tuple[stack_var_type, stack_var_type] = None,
) -> int:
    """
    Count stack_def_use.def_used tuples for a stack variable in the snippet

    If stack_var is None, count all in_bounds tuples.
    """
    count = 0
    bounds = snippets.snippet_bounds(module)
    for def_used in snippets.parse_souffle_output(
        module, "stack_def_use.def_used"
    ):
        if stack_var_pair is not None and (
            def_used[1] != stack_var_pair[0]
            or def_used[3] != stack_var_pair[1]
        ):
            continue
        if in_bounds(bounds, def_used[0]) and in_bounds(bounds, def_used[2]):
            count += 1
    return count


class StackVarTests(unittest.TestCase):
    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_stack_var_def_use(self):
        """
        Test a simple stack var def-use within a single block.
        """
        module = snippets.asm_to_gtirb(
            """
            # Define a stack frame
            subq $32,%rsp

            # Def a stack variable, and then use it.
            movq %rax,16(%rsp)
            movq 16(%rsp),%rax
            """
        )
        self.assertEqual(
            1,
            count_stack_def_use_in_snippet(module, (("RSP", 16), ("RSP", 16))),
        )

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_stack_var_def_use_two_blocks(self):
        """
        Test stack var def-use across two adjacent blocks.
        """
        module = snippets.asm_to_gtirb(
            """
            # Define a stack frame
            subq $32,%rsp

            # Def a stack variable
            movq %rax,16(%rsp)

            # Add control flow (splits blocks)
            test $0, %rax
            je .end

            # Use the stack variable
            movq 16(%rsp),%rax

            .end:
            """
        )
        self.assertEqual(
            1,
            count_stack_def_use_in_snippet(module, (("RSP", 16), ("RSP", 16))),
        )

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_stack_var_def_use_two_uses(self):
        """
        Test stack var def-use where a single def has two uses.
        """
        module = snippets.asm_to_gtirb(
            """
            # Define a stack frame
            subq $32,%rsp

            # Def a stack variable
            movq %rax,16(%rsp)

            # Add control flow (splits blocks)
            test $0, %rax
            je .end

            # Use the stack variable
            movq 16(%rsp),%rax

            # Add control flow (splits blocks)
            test $0, %rax
            je .end

            # Use the stack variable again
            movq 16(%rsp),%rax

            .end:
            """
        )
        self.assertEqual(
            2,
            count_stack_def_use_in_snippet(module, (("RSP", 16), ("RSP", 16))),
        )

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_stack_var_adjustment_intrablock(self):
        """
        Test stack var def-use within a block with a stack pointer adjustment.
        """
        module = snippets.asm_to_gtirb(
            """
            # Define a stack frame
            subq $32,%rsp

            # Add control flow (splits blocks)
            test $0, %rax
            je .end

            # Define a stack variable
            movq %rax,16(%rsp)

            # Adjust
            subq $24,%rsp

            # Use the stack variable
            movq 40(%rsp),%rax

            .end:
            """
        )
        self.assertEqual(
            1,
            count_stack_def_use_in_snippet(module, (("RSP", 16), ("RSP", 40))),
        )

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_stack_var_adjustment_intrablock_split(self):
        """
        Test stack var def-use within a block before two stack pointer
        adjustments
        """
        module = snippets.asm_to_gtirb(
            """
            # Define a stack frame
            subq $32,%rsp

            # Add control flow (splits blocks)
            test $0, %rax
            je .end

            # Define a stack variable
            movq %rax,16(%rsp)

            # Adjustment split in two parts
            subq $12,%rsp
            subq $12,%rsp

            # Use the stack variable
            movq 40(%rsp),%rax

            # Adjust again (should be irrelvant)
            subq $8,%rsp

            .end:
            """
        )
        self.assertEqual(
            1,
            count_stack_def_use_in_snippet(module, (("RSP", 16), ("RSP", 40))),
        )

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_stack_var_adjustment_intrablock_between_adjustments(self):
        """
        Test stack var def-use within a block between two stack pointer
        adjustments
        """
        module = snippets.asm_to_gtirb(
            """
            # Define a stack frame
            subq $12,%rsp

            # Adjust/redefine (same block)
            subq $8,%rsp

            # Define a stack variable
            movq %rax,16(%rsp)

            # Adjust the stack frame
            subq $24,%rsp

            # Use the stack variable
            movq 40(%rsp),%rax
            """
        )
        self.assertEqual(
            1,
            count_stack_def_use_in_snippet(module, (("RSP", 16), ("RSP", 40))),
        )

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_stack_var_def_and_adjust_then_used(self):
        """
        Test stack var def-use where a stack var is defined and the frame is
        adjusted in a block, and then it is used in a later block.
        """
        module = snippets.asm_to_gtirb(
            """
            # Define a stack frame
            subq $12,%rsp

            # Define a stack variable
            movq %rax,16(%rsp)

            # Adjust stack frame
            subq $24,%rsp

            # Add control flow (splits blocks)
            test $0, %rax
            je .end

            # Use the stack variable
            movq 40(%rsp),%rax

            .end:
            """
        )
        self.assertEqual(
            1,
            count_stack_def_use_in_snippet(module, (("RSP", 16), ("RSP", 40))),
        )

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_stack_var_def_then_adjust_and_used(self):
        """
        Test stack var def-use where a stack var is defined, and then the frame
        adjusted and the var used in a later block.
        """
        module = snippets.asm_to_gtirb(
            """
            # Define a stack frame
            subq $12,%rsp

            # Define a stack variable
            movq %rax,16(%rsp)

            # Add control flow (splits blocks)
            test $0, %rax
            je .end

            # Adjust stack frame
            subq $24,%rsp

            # Use the stack variable
            movq 40(%rsp),%rax

            .end:
            """
        )
        self.assertEqual(
            1,
            count_stack_def_use_in_snippet(module, (("RSP", 16), ("RSP", 40))),
        )

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_stack_var_def_adjust_used(self):
        """
        Test stack var def-use where a stack var is defined, adjusted, and then
        used in separate blocks.
        """
        module = snippets.asm_to_gtirb(
            """
            # Define a stack frame
            subq $12,%rsp

            # Define a stack variable
            movq %rax,16(%rsp)

            # Add control flow (splits blocks)
            test $0, %rax
            je .end

            # Adjust stack frame
            subq $24,%rsp

            # Add control flow (splits blocks)
            test $0, %rax
            je .end

            # Use the stack variable
            movq 40(%rsp),%rax

            .end:
            """
        )
        self.assertEqual(
            1,
            count_stack_def_use_in_snippet(module, (("RSP", 16), ("RSP", 40))),
        )

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_stack_var_move_base_reg_intrablock(self):
        """
        Test stack var def-use where a stack var is defined, and the stack
        pointer is moved to the frame pointer.

        A MIPS-specific rule for this pattern used to exist, but it has been
        made redudant with arch-generic recognition.
        """
        module = snippets.asm_to_gtirb(
            """
            # Define a stack frame
            subq $12,%rsp

            # Define a stack variable
            movq %rax,16(%rsp)

            # Move stack pointer to frame pointer
            movq %rsp,%rbp

            # Use the stack variable via the frame pointer
            movq 16(%rbp),%rax

            .end:
            """
        )
        self.assertEqual(
            1,
            count_stack_def_use_in_snippet(module, (("RSP", 16), ("RBP", 16))),
        )

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_stack_var_move_base_reg_interblock1(self):
        """
        Test stack var def-use where a stack var is defined, and the stack
        pointer is moved to the frame pointer.

        In this case, the def and move occur in the same block, but not the use
        """
        module = snippets.asm_to_gtirb(
            """
            # Define a stack frame
            subq $12,%rsp

            # Define a stack variable
            movq %rax,16(%rsp)

            # Move stack pointer to frame pointer
            movq %rsp,%rbp

            # Add control flow (splits blocks)
            test $0, %rax
            je .end

            # Use the stack variable via the frame pointer
            movq 16(%rbp),%rax

            .end:
            """
        )
        self.assertEqual(
            1,
            count_stack_def_use_in_snippet(module, (("RSP", 16), ("RBP", 16))),
        )

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_stack_var_move_base_reg_interblock2(self):
        """
        Test stack var def-use where a stack var is defined, and the stack
        pointer is moved to the frame pointer.

        In this case, the def occurs in one block, and the move and use in
        another.
        """
        module = snippets.asm_to_gtirb(
            """
            # Define a stack frame
            subq $12,%rsp

            # Define a stack variable
            movq %rax,16(%rsp)

            # Add control flow (splits blocks)
            test $0, %rax
            je .end

            # Move stack pointer to frame pointer
            movq %rsp,%rbp

            # Use the stack variable via the frame pointer
            movq 16(%rbp),%rax

            .end:
            """
        )
        self.assertEqual(
            1,
            count_stack_def_use_in_snippet(module, (("RSP", 16), ("RBP", 16))),
        )

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_stack_var_move_base_reg_interblock3(self):
        """
        Test stack var def-use where a stack var is defined, and the stack
        pointer is moved to the frame pointer.

        In this case, the def, move, and use occur in different blocks.
        """
        module = snippets.asm_to_gtirb(
            """
            # Define a stack frame
            subq $12,%rsp

            # Define a stack variable
            movq %rax,16(%rsp)

            # Add control flow (splits blocks)
            test $0, %rax
            je .end

            # Move stack pointer to frame pointer
            movq %rsp,%rbp

            # Add control flow (splits blocks)
            test $0, %rax
            je .end

            # Use the stack variable via the frame pointer
            movq 16(%rbp),%rax

            .end:
            """
        )
        self.assertEqual(
            1,
            count_stack_def_use_in_snippet(module, (("RSP", 16), ("RBP", 16))),
        )

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_stack_var_adjustment_intrablock_redef(self):
        """
        Test stack var def-use within a block with a stack pointer adjustment.
        """
        module = snippets.asm_to_gtirb(
            """
            # Define a stack frame
            subq $32,%rsp

            # Define a stack variable
            movq %rax,16(%rsp)

            # Adjust
            subq $24,%rsp

            # Redefine stack pointer (not an adjustment)
            movq %rax,%rsp

            # Use the stack variable
            movq 40(%rsp),%rax

            .end:
            """
        )

        # There should be no def_used for snippet
        self.assertEqual(0, count_stack_def_use_in_snippet(module))

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_stack_var_adjustment_interblock_redef_after_use(self):
        """
        Test stack var def-use with adjustment where the stack pointer is
        redefined after a use.
        """
        module = snippets.asm_to_gtirb(
            """
            # Define a stack frame
            subq $32,%rsp

            # Define a stack variable
            movq %rax,16(%rsp)

            # Add control flow (splits blocks)
            test $0, %rax
            je .end

            # Adjust
            subq $24,%rsp

            # Use the stack variable
            movq 40(%rsp),%rax

            # Redefine stack pointer (not an adjustment)
            movq %rax,%rsp

            .end:
            """
        )

        self.assertEqual(
            1,
            count_stack_def_use_in_snippet(module, (("RSP", 16), ("RSP", 40))),
        )

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_adjusted_killing_use(self):
        """
        Test that a definition before adjustment
        kills the corresponding use.
        """
        module = snippets.asm_to_gtirb(
            """
            # Define a stack frame
            subq $32,%rsp

            # Define a stack variable
            movq %rax,16(%rsp)

            # Add control flow (splits blocks)
            test $0, %rax
            je .end

            # Redefine (the later use is killed and should not be
            # matched with the previous definition)
            movq %rax,16(%rsp)

            # Adjust
            subq $24,%rsp

            # Use the stack variable
            movq 40(%rsp),%rax

            .end:
            """
        )

        self.assertEqual(
            1,
            count_stack_def_use_in_snippet(module, (("RSP", 16), ("RSP", 40))),
        )

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_adjusted_killing_def(self):
        """
        Test that a definition before adjustment
        is killed by the definition after the adjustment.
        """
        module = snippets.asm_to_gtirb(
            """
            # Define a stack frame
            subq $32,%rsp

            # Define a stack variable
            movq %rax,16(%rsp)

            # Adjust
            subq $24,%rsp

            # Redefine, this kills the previous definition.
            movq %rax,40(%rsp)

            # Add control flow (splits blocks)
            test $0, %rax
            je .end

            # Use the stack variable
            movq 40(%rsp),%rax

            .end:
            """
        )

        self.assertEqual(
            0,
            count_stack_def_use_in_snippet(module, (("RSP", 16), ("RSP", 40))),
        )
        self.assertEqual(
            1,
            count_stack_def_use_in_snippet(module, (("RSP", 40), ("RSP", 40))),
        )

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_adjusted_killing_use_intrablock(self):
        """
        Test that a definition before adjustment
        kills the corresponding use.
        """
        module = snippets.asm_to_gtirb(
            """
            # Define a stack frame
            subq $32,%rsp

            # Define a stack variable
            movq %rax,16(%rsp)

            # Add control flow (splits blocks)
            test $0, %rax
            je .end

            # Redefine (the later use is killed and should not be
            # matched with the previous definition)
            movq %rax,16(%rsp)

            # Adjust
            subq $24,%rsp

            # Add control flow (splits blocks)
            test $0, %rax
            je .end

            # Use the stack variable
            movq 40(%rsp),%rax

            .end:
            """
        )

        self.assertEqual(
            1,
            count_stack_def_use_in_snippet(module, (("RSP", 16), ("RSP", 40))),
        )
