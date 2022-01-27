#!/usr/bin/env python3
import argparse
import gtirb
import sys


def lookup_sym(node):
    for sym in node.module.symbols:
        if sym._payload == node:
            return sym.name


def node_str(node):
    if isinstance(node, gtirb.ProxyBlock):
        return lookup_sym(node) or node.uuid
    else:
        return hex(node.address)


def has_undefined_branch(branches):
    for branch in branches:
        if isinstance(branch.target, gtirb.ProxyBlock) and not lookup_sym(
            branch.target
        ):
            return True
    return False


def has_symbolic_branch(branches):
    for branch in branches:
        if lookup_sym(branch.target):
            return True
    return False


def is_skipped_section(node):
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


def get_func_entry_name(node):
    """
    If the node is the entry point to a function, return the function name.

    Otherwise returns None
    """
    for key, value in node.module.aux_data["functionNames"].data.items():
        if node in node.module.aux_data["functionEntries"].data[key]:
            return value.name


def belongs_to_skipped_func(node):
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


def is_padding(node):
    for key, padding_size in node.module.aux_data["padding"].data.items():
        padding_addr = key.element_id.address + key.displacement

        if padding_addr == node.address:
            return True

    return False


def check_gtirb_cfg(path):
    """
    Determine if a GTIRB file has a CFG with:

    * Unreachable code
    * Unresolved jumps
    """
    error_count = 0
    checked_node_count = 0
    module = gtirb.IR.load_protobuf(path).modules[0]

    for node in module.cfg_nodes:
        if (
            not isinstance(node, gtirb.CodeBlock)
            or belongs_to_skipped_func(node)
            or is_padding(node)
        ):
            continue
        checked_node_count += 1

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

    if checked_node_count == 0:
        print("ERROR: CFG has no nodes")
        error_count += 1

    return error_count


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("path")
    args = parser.parse_args()
    sys.exit(check_gtirb_cfg(args.path))
