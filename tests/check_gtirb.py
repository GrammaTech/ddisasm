#!/usr/bin/env python3
import argparse
from typing import List, Union
import sys

import capstone_gt
import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder


def lookup_sym(node: gtirb.Block) -> Union[str, None]:
    """
    Find a symbol name that describes the node.
    """
    for sym in node.module.symbols:
        if sym._payload == node:
            return sym.name


def node_str(node: gtirb.Block) -> str:
    """
    Generate a string that uniquely identifies the node
    """
    if isinstance(node, gtirb.ProxyBlock):
        return lookup_sym(node) or node.uuid
    else:
        return hex(node.address)


def has_undefined_branch(branches: List[gtirb.Edge]) -> bool:
    """
    Determine if any of the branches are not resolved to a target.
    """
    for branch in branches:
        if isinstance(branch.target, gtirb.ProxyBlock) and not lookup_sym(
            branch.target
        ):
            return True
    return False


def has_symbolic_branch(branches: List[gtirb.Edge]) -> bool:
    """
    Determine if any of the branches are to a defined symbol.
    """
    for branch in branches:
        if lookup_sym(branch.target):
            return True
    return False


def is_skipped_section(node: gtirb.CodeBlock) -> bool:
    """
    Determine if the node is part of an uninteresting section.
    """
    skipped_sections = [
        ".plt",
        ".init",
        ".fini",
        ".MIPS.stubs",
    ]

    for section in node.module.sections:
        if section.name not in skipped_sections:
            continue

        for interval in section.byte_intervals:
            start = interval.address
            end = interval.address + interval.size

            if start <= node.address and node.address < end:
                return True
    return False


def get_func_entry_name(node: gtirb.CodeBlock) -> Union[str, None]:
    """
    If the node is the entry point to a function, return the function name.

    Otherwise returns None
    """
    for key, value in node.module.aux_data["functionNames"].data.items():
        if node in node.module.aux_data["functionEntries"].data[key]:
            return value.name


def belongs_to_skipped_func(node: gtirb.CodeBlock) -> bool:
    """
    Determine if a CFG node is
    """
    skipped_funcs = [
        "__do_global_ctors_aux",
        "__do_global_dtors_aux",
        "__libc_csu_fini",
        "__libc_csu_init",
        "_dl_relocate_static_pie",
        "_start",
        "deregister_tm_clones",
        "frame_dummy",
        "register_tm_clones",
    ]

    for name in skipped_funcs:
        for key, value in node.module.aux_data["functionNames"].data.items():
            if value.name == name:
                if node in node.module.aux_data["functionBlocks"].data[key]:
                    return True

    return is_skipped_section(node)


def is_padding(node: gtirb.CodeBlock) -> bool:
    """
    Determine if a CFG node is padding
    """
    for key, padding_size in node.module.aux_data["padding"].data.items():
        padding_addr = key.element_id.address + key.displacement

        if padding_addr == node.address:
            return True

    return False


def check_unreachable(module: gtirb.Module) -> int:
    """
    Check a GTIRB module for unexpected unreachable code
    """
    error_count = 0

    for node in module.cfg_nodes:
        if (
            not isinstance(node, gtirb.CodeBlock)
            or belongs_to_skipped_func(node)
            or is_padding(node)
        ):
            continue

        func = get_func_entry_name(node)
        if len(list(node.incoming_edges)) == 0 and func != "main":

            if func:
                # In some cases in our examples, function call sites are
                # optimized away, but the function is left in the binary.
                # We warn for these - if this code isn't being run, we're not
                # testing whether ddisasm disassembled it well, and we may want
                # to consider reworking those examples.
                print(
                    'WARNING: unreachable function "{}" at {}'.format(
                        func, node_str(node)
                    )
                )
            else:
                # Unreachable code that is not a function entry is likely to
                # be an error, such as jump table where not all possible
                # targets were discovered.
                print("ERROR: unreachable code at", node_str(node))
                error_count += 1

    return error_count


def check_unresolved_branch(module: gtirb.Module) -> int:
    """
    Check a GTIRB module for unresolved branches
    """
    error_count = 0

    for node in module.cfg_nodes:
        if (
            not isinstance(node, gtirb.CodeBlock)
            or belongs_to_skipped_func(node)
            or is_padding(node)
        ):
            continue

        branches = []

        for edge in node.outgoing_edges:
            if edge.label.type not in (
                gtirb.Edge.Type.Return,
                gtirb.Edge.Type.Fallthrough,
            ):
                branches.append(edge)

        # Calls to PLT functions seem to have a branch to a ProxyBlock for
        # that symbol and a branch to the original PLT function.
        if has_undefined_branch(branches) and not has_symbolic_branch(
            branches
        ):
            print("ERROR: unresolved jump in", node_str(node))
            error_count += 1

    return error_count


def check_cfg_empty(module: gtirb.Module) -> int:
    """
    Check if a GTIRB module has an empty CFG
    """
    if len(list(module.cfg_nodes)) == 0:
        print("ERROR: CFG has no nodes")
        return 1

    return 0


def check_main_is_code(module: gtirb.Module) -> int:
    """
    Check a GTIRB module for a `main` symbol that is not a CodeBlock.

    Returns the number of errors found.
    """
    error_count = 0

    for sym in module.symbols:
        if sym.name == "main":
            if not isinstance(sym.referent, gtirb.CodeBlock):
                print("ERROR: main is not code")
                error_count += 1

    return error_count


def check_decode_mode_matches_arch(module: gtirb.Module) -> int:
    """
    Ensure a GTIRB only uses DecodeMode values that match the architecture

    Returns the number of errors found.
    """
    error_count = 0

    # if a new mode is added, we will raise a KeyError unless it is added
    # to this dictionary.
    mode_to_arch = {
        gtirb.CodeBlock.DecodeMode.Thumb: gtirb.module.Module.ISA.ARM
    }

    for block in module.code_blocks:
        if block.decode_mode == gtirb.CodeBlock.DecodeMode.Default:
            # "Default" is correct on every arch
            continue

        if module.isa != mode_to_arch[block.decode_mode]:
            print(f"ERROR: {module.isa} does not support {block.decode_mode}")
            error_count += 1

    return error_count


def check_outgoing_edges(module: gtirb.Module) -> int:
    """
    Check outgoing edges for invalid configurations
    """
    error_count = 0

    for node in module.cfg_nodes:
        fallthrough_count = 0
        direct_call_count = 0
        direct_jump_count = 0

        for edge in node.outgoing_edges:

            if edge.label.direct and edge.label.type == gtirb.Edge.Type.Call:
                direct_call_count += 1
            elif (
                edge.label.direct and edge.label.type == gtirb.Edge.Type.Branch
            ):
                direct_jump_count += 1
            elif edge.label.type == gtirb.Edge.Type.Fallthrough:
                fallthrough_count += 1

        if fallthrough_count > 1:
            print("ERROR: multiple fallthrough from ", node_str(node))
            error_count += 1
        if direct_call_count > 1:
            print("ERROR: multiple direct call from ", node_str(node))
            error_count += 1
        if direct_jump_count > 1:
            print("ERROR: multiple direct jump from ", node_str(node))
            error_count += 1

    return error_count


def is_rep_loop(inst: capstone_gt.CsInsn) -> bool:
    """
    Check if an instruction is a rep/repe/repne loop
    """
    return inst.prefix[0] in [
        capstone_gt.x86.X86_PREFIX_REP,
        capstone_gt.x86.X86_PREFIX_REPE,
        capstone_gt.x86.X86_PREFIX_REPNE,
    ]


def is_direct(inst: capstone_gt.CsInsn) -> bool:
    """
    Check if a call or jump instruction is direct
    """
    assert any(
        inst.group(grp)
        for grp in (
            capstone_gt.x86.X86_GRP_CALL,
            capstone_gt.x86.X86_GRP_JUMP,
            capstone_gt.x86.X86_GRP_BRANCH_RELATIVE,
        )
    )
    target = inst.operands[0]
    return target.type == capstone_gt.CS_OP_IMM


def is_pc_relative(inst: capstone_gt.CsInsn) -> bool:
    """
    Check if a call or jump instruction is pc-relative
    """
    assert any(
        inst.group(grp)
        for grp in (
            capstone_gt.x86.X86_GRP_CALL,
            capstone_gt.x86.X86_GRP_JUMP,
            capstone_gt.x86.X86_GRP_BRANCH_RELATIVE,
        )
    )
    target = inst.operands[0]
    return (
        target.type == capstone_gt.CS_OP_MEM
        and inst.reg_name(target.mem.base) == "rip"
    )


def check_edge_instruction_group(module: gtirb.Module) -> int:
    """
    Check edges for valid instruction groups
    """
    # TODO: support non-x86 checks
    if module.isa not in [gtirb.Module.ISA.X64, gtirb.Module.ISA.IA32]:
        return 0

    err_count = 0
    decoder = GtirbInstructionDecoder(module.isa)

    # TODO: there is one more generic capstone group, X86_GRP_PRIVILEGE.
    # does it belong in Syscall?
    edge_type_groups = {
        gtirb.Edge.Type.Branch: set(
            (
                capstone_gt.x86.X86_GRP_JUMP,
                capstone_gt.x86.X86_GRP_BRANCH_RELATIVE,
            )
        ),
        gtirb.Edge.Type.Call: set((capstone_gt.x86.X86_GRP_CALL,)),
        gtirb.Edge.Type.Return: set((capstone_gt.x86.X86_GRP_RET,)),
        gtirb.Edge.Type.Syscall: set((capstone_gt.x86.X86_GRP_INT,)),
        gtirb.Edge.Type.Sysret: set((capstone_gt.x86.X86_GRP_IRET,)),
    }

    for edge in module.ir.cfg:
        if edge.label.type == gtirb.Edge.Type.Fallthrough:
            # fallthrough edges do not map to a specified instruction group
            continue

        block = edge.source

        # get the last instruction
        for instruction in decoder.get_instructions(block):
            last_inst = instruction

        # ensure instruction can be an edge

        # Instructions with rep prefix can have self-edge
        if (
            edge.label.type == gtirb.Edge.Type.Branch
            and is_rep_loop(last_inst)
            and edge.target == block
        ):
            continue

        valid_groups = edge_type_groups[edge.label.type]
        if not any(last_inst.group(grp) for grp in valid_groups):
            print(
                "ERROR: invalid edge instruction group at 0x{:08x}: {}".format(
                    last_inst.address, last_inst.groups
                )
            )
            err_count += 1

    return err_count


def check_cfg_completeness(module: gtirb.Module) -> int:
    """
    Check we have 1 call/branch edge from all direct or
    pc-relative calls/jumps.
    """
    # TODO: support non-x86 checks
    if module.isa not in [gtirb.Module.ISA.X64, gtirb.Module.ISA.IA32]:
        return 0

    err_count = 0
    decoder = GtirbInstructionDecoder(module.isa)

    for block in module.code_blocks:
        # get the last instruction
        for instruction in decoder.get_instructions(block):
            last_inst = instruction
        if last_inst.group(capstone_gt.x86.X86_GRP_CALL):
            call_edges = [
                edge
                for edge in block.outgoing_edges
                if edge.label.type == gtirb.EdgeType.Call
            ]
            if is_direct(last_inst) or is_pc_relative(last_inst):

                # do not count if we are using the 'call next; next: pop'
                # trick to get the PC value.
                if (
                    is_direct(last_inst)
                    and module.isa == gtirb.Module.ISA.IA32
                    and last_inst.operands[0].imm
                    == last_inst.address + last_inst.size
                ):
                    continue

                if len(call_edges) != 1:
                    print(
                        "ERROR: expected 1 call edge at "
                        f"0x{last_inst.address:08x} and got {len(call_edges)}"
                    )
                    err_count += 1
        elif last_inst.group(capstone_gt.x86.X86_GRP_JUMP):

            # The first block of plt sections looks like:
            #    pushq .got.plt+8(%rip)
            #    jmpq *.got.plt+16(%rip)  <----
            # And the first 3 entries of .got.plt (or .got) are:
            #    .quad link-time address of _DYNAMIC  # set by linker
            #    .quad Obj_Entry  # set by ld.so
            #    .quad _rtld_bind_start  # set by ld.so
            # Currently we don't generate an edge for that
            # jump because .got.plt+16 has a 0 and no relocations.
            if (
                block.section.address == block.address
                and block.section.name in [".plt", ".plt.sec", ".plt.got"]
            ):
                continue

            branch_edges = [
                edge
                for edge in block.outgoing_edges
                if edge.label.type == gtirb.EdgeType.Branch
            ]
            if is_direct(last_inst) or is_pc_relative(last_inst):
                if len(branch_edges) != 1:
                    print(
                        "ERROR: expected 1 branch edge at "
                        f"0x{last_inst.address:08x} and got"
                        f" {len(branch_edges)}"
                    )
                    err_count += 1

    return err_count


CHECKS = {
    "unreachable": check_unreachable,
    "unresolved_branch": check_unresolved_branch,
    "cfg_empty": check_cfg_empty,
    "main_is_code": check_main_is_code,
    "decode_mode_matches_arch": check_decode_mode_matches_arch,
    "outgoing_edges": check_outgoing_edges,
    "edge_instruction_group": check_edge_instruction_group,
    "cfg_completeness": check_cfg_completeness,
}


class NoSuchCheckError(Exception):
    """Indicates an invalid GTIRB check was specified"""

    pass


def run_checks(module: gtirb.Module, selected_checks: List[str]):
    """
    Run specified checks

    Raises NoSuchCheckError for unexpected names in selected_checks
    """
    error_count = 0
    for selected_check in selected_checks:
        if selected_check not in CHECKS:
            raise NoSuchCheckError(f"No such check: {selected_check}")

        error_count += CHECKS[selected_check](module)

    return error_count


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("path")

    check_names = list(CHECKS.keys())
    check_names.append("all")

    parser.add_argument(
        "--check",
        choices=check_names,
        default="all",
        help="The name of the check to run",
    )
    args = parser.parse_args()

    module = gtirb.IR.load_protobuf(args.path).modules[0]
    checks = list(CHECKS.keys()) if args.check == "all" else [args.check]
    error_count = run_checks(module, checks)
    sys.exit(error_count)


if __name__ == "__main__":
    main()
