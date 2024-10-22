import platform
import unittest
from disassemble_reassemble_check import compile, cd, disassemble
from pathlib import Path
import gtirb


ex_asm_dir = Path("./examples/") / "asm_examples"


def addr_in_function(
    module: gtirb.Module, addr: int, function_name: str
) -> bool:
    """
    Determine whether an address is part of a given function.
    """
    for key, value in module.aux_data["functionNames"].data.items():
        if value.name == function_name:
            function = key
            break
    else:
        raise Exception(f"No such function: {function_name}")

    for node in module.aux_data["functionBlocks"].data[function]:
        if node.address <= addr and addr < node.address + node.size:
            return True

    return False


class DefUsedTests(unittest.TestCase):
    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_def_used_through_return(self):
        """
        Test that def_used detects values defined in a function and used after
        return.
        """
        binary = Path("ex")
        with cd(ex_asm_dir / "ex_return_use_def"):
            self.assertTrue(compile("gcc", "g++", "-O0", []))
            ir_library = disassemble(
                binary,
                strip=False,
                extra_args=["--with-souffle-relations"],
            ).ir()
            m = ir_library.modules[0]

            # Confirm a def_used exists where it is defined in the `get_ptr`
            # function and used in `main`.
            def_used = (
                m.aux_data["souffleOutputs"]
                .data["disassembly.reg_def_use.def_used"][1]
                .strip()
                .split("\n")
            )
            for tupl in def_used:
                tupl = tupl.split("\t")

                ea_def = int(tupl[0], 0)
                ea_used = int(tupl[2], 0)

                if addr_in_function(m, ea_def, "get_ptr") and addr_in_function(
                    m, ea_used, "main"
                ):
                    break
            else:
                # for ... else: did not find the def_used we're looking for.
                self.fail("No def_used for returned value")


if __name__ == "__main__":
    unittest.main()
