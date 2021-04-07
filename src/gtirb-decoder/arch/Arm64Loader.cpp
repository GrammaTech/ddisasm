//===- Arm64Loader.cpp ------------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2020 GrammaTech, Inc.
//
//  This code is licensed under the GNU Affero General Public License
//  as published by the Free Software Foundation, either version 3 of
//  the License, or (at your option) any later version. See the
//  LICENSE.txt file in the project root for license terms or visit
//  https://www.gnu.org/licenses/agpl.txt.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
//  GNU Affero General Public License for more details.
//
//  This project is sponsored by the Office of Naval Research, One Liberty
//  Center, 875 N. Randolph Street, Arlington, VA 22203 under contract #
//  N68335-17-C-0700.  The content of the information does not necessarily
//  reflect the position or policy of the Government and no official
//  endorsement should be inferred.
//
//===----------------------------------------------------------------------===//
#include "Arm64Loader.h"

#include <algorithm>
#include <string>
#include <vector>

void Arm64Loader::insert(const Arm64Facts& Facts, DatalogProgram& Program)
{
    auto& [Instructions, Operands] = Facts;
    Program.insert("instruction", Instructions.instructions());
    Program.insert("invalid_op_code", Instructions.invalid());
    Program.insert("op_immediate", Operands.imm());
    Program.insert("op_regdirect", Operands.reg());
    Program.insert("op_indirect", Operands.indirect());
    Program.insert("op_barrier", Operands.barrier());
    Program.insert("op_prefetch", Operands.prefetch());
}

void Arm64Loader::decode(Arm64Facts& Facts, const uint8_t* Bytes, uint64_t Size, uint64_t Addr)
{
    // Decode instruction with Capstone.
    cs_insn* CsInsn;
    size_t Count = cs_disasm(*CsHandle, Bytes, Size, Addr, 1, &CsInsn);

    // Build datalog instruction facts from Capstone instruction.
    std::optional<relations::Instruction> Instruction;
    if(Count > 0)
    {
        Instruction = build(Facts, *CsInsn);
    }

    if(Instruction)
    {
        // Add the instruction to the facts table.
        Facts.Instructions.add(*Instruction);
    }
    else
    {
        // Add address to list of invalid instruction locations.
        Facts.Instructions.invalid(gtirb::Addr(Addr));
    }

    cs_free(CsInsn, Count);
}

std::optional<relations::Instruction> Arm64Loader::build(Arm64Facts& Facts,
                                                         const cs_insn& CsInstruction)
{
    const cs_arm64& Details = CsInstruction.detail->arm64;
    std::string Name = uppercase(CsInstruction.mnemonic);
    std::vector<uint64_t> OpCodes;

    if(Name != "NOP")
    {
        int OpCount = Details.op_count;
        for(int i = 0; i < OpCount; i++)
        {
            // Load capstone operand.
            const cs_arm64_op& CsOp = Details.operands[i];

            // Build operand for datalog fact.
            std::optional<relations::Arm64Operand> Op = build(CsOp);
            if(!Op)
            {
                return std::nullopt;
            }

            // Add operand to the operands table.
            uint64_t OpIndex = Facts.Operands.add(*Op);
            OpCodes.push_back(OpIndex);
        }
        // Put the destination operand at the end of the operand list.
        if(OpCount > 0)
        {
            std::rotate(OpCodes.begin(), OpCodes.begin() + 1, OpCodes.end());
        }
    }

    gtirb::Addr Addr(CsInstruction.address);
    uint64_t Size(CsInstruction.size);
    return relations::Instruction{Addr, Size, "", Name, OpCodes, 0, 0};
}

std::optional<relations::Arm64Operand> Arm64Loader::build(const cs_arm64_op& CsOp)
{
    using namespace relations;

    auto registerName = [this](unsigned int Reg) {
        return (Reg == ARM_REG_INVALID) ? "NONE" : uppercase(cs_reg_name(*CsHandle, Reg));
    };

    switch(CsOp.type)
    {
        case ARM64_OP_REG:
            return RegOp{registerName(CsOp.reg)};
        case ARM64_OP_IMM:
            return ImmOp{CsOp.imm};
        case ARM64_OP_MEM:
        {
            IndirectOp I = {registerName(ARM64_REG_INVALID),
                            registerName(CsOp.mem.base),
                            registerName(CsOp.mem.index),
                            1,
                            CsOp.mem.disp,
                            4 * 8};
            return I;
        }
        case ARM64_OP_FP:
            std::cerr << "unsupported: FP\n";
            break;
        case ARM64_OP_CIMM:
            std::cerr << "unsupported: CIMM\n";
            break;
        case ARM64_OP_REG_MRS:
            std::cerr << "unsupported: MRS\n";
            break;
        case ARM64_OP_REG_MSR:
            std::cerr << "unsupported: MSR\n";
            break;
        case ARM64_OP_PSTATE:
            std::cerr << "unsupported: PSTATE\n";
            break;
        case ARM64_OP_SYS:
            std::cerr << "unsupported: SYS\n";
            break;
        case ARM64_OP_PREFETCH:
        {
            if(std::optional<const char*> Label = prefetchValue(CsOp.prefetch))
            {
                return PrefetchOp{*Label};
            }
            break;
        }
        case ARM64_OP_BARRIER:
        {
            if(std::optional<const char*> Label = barrierValue(CsOp.barrier))
            {
                return BarrierOp{*Label};
            }
            break;
        }
        case ARM64_OP_INVALID:
        default:
            break;
    }
    return std::nullopt;
}

std::optional<const char*> prefetchValue(const arm64_prefetch_op Op)
{
    switch(Op)
    {
        case ARM64_PRFM_PLDL1KEEP:
            return "pldl1keep";
        case ARM64_PRFM_PLDL1STRM:
            return "pldl1strm";
        case ARM64_PRFM_PLDL2KEEP:
            return "pldl2keep";
        case ARM64_PRFM_PLDL2STRM:
            return "pldl2strm";
        case ARM64_PRFM_PLDL3KEEP:
            return "pldl3keep";
        case ARM64_PRFM_PLDL3STRM:
            return "pldl3strm";
        case ARM64_PRFM_PLIL1KEEP:
            return "plil1keep";
        case ARM64_PRFM_PLIL1STRM:
            return "plil1strm";
        case ARM64_PRFM_PLIL2KEEP:
            return "plil2keep";
        case ARM64_PRFM_PLIL2STRM:
            return "plil2strm";
        case ARM64_PRFM_PLIL3KEEP:
            return "plil3keep";
        case ARM64_PRFM_PLIL3STRM:
            return "plil3strm";
        case ARM64_PRFM_PSTL1KEEP:
            return "pstl1keep";
        case ARM64_PRFM_PSTL1STRM:
            return "pstl1strm";
        case ARM64_PRFM_PSTL2KEEP:
            return "pstl2keep";
        case ARM64_PRFM_PSTL2STRM:
            return "pstl2strm";
        case ARM64_PRFM_PSTL3KEEP:
            return "pstl3keep";
        case ARM64_PRFM_PSTL3STRM:
            return "pstl3strm";
        case ARM64_PRFM_INVALID:
        default:
            break;
    }
    return std::nullopt;
}

std::optional<const char*> barrierValue(const arm64_barrier_op Op)
{
    switch(Op)
    {
        case ARM64_BARRIER_OSHLD:
            return "oshld";
        case ARM64_BARRIER_OSHST:
            return "oshst";
        case ARM64_BARRIER_OSH:
            return "osh";
        case ARM64_BARRIER_NSHLD:
            return "nshld";
        case ARM64_BARRIER_NSHST:
            return "nshst";
        case ARM64_BARRIER_NSH:
            return "nsh";
        case ARM64_BARRIER_ISHLD:
            return "ishld";
        case ARM64_BARRIER_ISHST:
            return "ishst";
        case ARM64_BARRIER_ISH:
            return "ish";
        case ARM64_BARRIER_LD:
            return "ld";
        case ARM64_BARRIER_ST:
            return "st";
        case ARM64_BARRIER_SY:
            return "sy";
        case ARM64_BARRIER_INVALID:
        default:
            break;
    }
    return std::nullopt;
}

namespace souffle
{
    souffle::tuple& operator<<(souffle::tuple& T, const relations::BarrierOp& Op)
    {
        T << Op.Value;
        return T;
    }

    souffle::tuple& operator<<(souffle::tuple& T, const relations::PrefetchOp& Op)
    {
        T << Op.Value;
        return T;
    }
} // namespace souffle
