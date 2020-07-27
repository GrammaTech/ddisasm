//===- Arm64Decoder.cpp -----------------------------------------*- C++ -*-===//
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

#include "Arm64Decoder.h"

#include <algorithm>
#include <string>

const char* prefetchValue(const arm64_prefetch_op prefetch)
{
    switch(prefetch)
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
            std::cerr << "invalid operand (prefetch)\n";
            exit(1);
    }
}

const char* barrierOp(const arm64_barrier_op barrier)
{
    switch(barrier)
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
            std::cerr << "invalid operand (barrier)\n";
            exit(1);
    }
}

std::optional<Arm64Decoder::Instruction> Arm64Decoder::disasm(const uint8_t* Bytes, uint64_t Size,
                                                              uint64_t Addr)
{
    cs_insn* Instruction;
    size_t Count = cs_disasm(CsHandle, Bytes, Size, Addr, 1, &Instruction);
    if(Count > 0)
    {
        return build(*Instruction);
    }
    cs_free(Instruction, Count);
    return std::nullopt;
}

std::optional<Arm64Decoder::Instruction> Arm64Decoder::build(const cs_insn& CsInstruction)
{
    cs_arm64& Details = CsInstruction.detail->arm64;
    // FIXME: Do we actually need this for ARM?
    auto [Prefix, Name] = splitMnemonic(CsInstruction);
    std::vector<uint64_t> OpCodes;

    if(Name != "NOP")
    {
        int OpCount = Details.op_count;
        for(int i = 0; i < OpCount; i++)
        {
            // Load capstone operand.
            cs_arm64_op& CsOp = Details.operands[i];

            // Build operand for datalog fact.
            std::optional<Arm64Decoder::Operand> Op = build(CsOp);
            if(!Op)
            {
                return std::nullopt;
            }

            // Add operand to the operands table.
            uint64_t OpIndex = std::visit(Operands, *Op);
            OpCodes.push_back(OpIndex);
        }
        // Put the destination operand at the end of the operand list.
        if(OpCount > 0)
        {
            std::rotate(OpCodes.begin(), OpCodes.begin() + 1, OpCodes.end());
        }
    }

    uint64_t Addr(CsInstruction.address), Size(CsInstruction.size);
    return Instruction{Addr, Size, Prefix, Name, OpCodes, 0, 0};
}

std::tuple<std::string, std::string> Arm64Decoder::splitMnemonic(const cs_insn& CsInstruction)
{
    // FIXME:
    auto str_toupper = [](std::string s) {
        std::transform(s.begin(), s.end(), s.begin(),
                       [](unsigned char c) { return static_cast<unsigned char>(std::toupper(c)); });
        return s;
    };

    std::string PrefixName = str_toupper(CsInstruction.mnemonic);
    std::string Prefix, Name;
    size_t Pos = PrefixName.find(' ');
    if(Pos != std::string::npos)
    {
        Prefix = PrefixName.substr(0, Pos);
        Name = PrefixName.substr(Pos + 1);
    }
    else
    {
        Prefix = "";
        Name = PrefixName;
    }
    return {Prefix, Name};
}

std::optional<Arm64Decoder::Operand> Arm64Decoder::build(const cs_arm64_op& CsOp)
{
    // FIXME:
    auto str_toupper = [](std::string s) {
        std::transform(s.begin(), s.end(), s.begin(),
                       [](unsigned char c) { return static_cast<unsigned char>(std::toupper(c)); });
        return s;
    };

    auto registerName = [str_toupper, this](uint64_t Reg) {
        return (Reg == ARM_REG_INVALID) ? "NONE" : str_toupper(cs_reg_name(CsHandle, Reg));
    };

    switch(CsOp.type)
    {
        case ARM64_OP_REG:
            return registerName(CsOp.reg);
        case ARM64_OP_IMM:
            return CsOp.imm;
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
            PrefetchOp I = {prefetchValue(CsOp.prefetch)};
            return I;
        }
        case ARM64_OP_BARRIER:
        {
            BarrierOp I = {barrierOp(CsOp.barrier)};
            return I;
        }
        case ARM64_OP_INVALID:
        default:
            std::cerr << "invalid operand\n";
            break;
    }
    return std::nullopt;
}
