//===- X64Decoder.cpp -------------------------------------------*- C++ -*-===//
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
//  GNU Affero General Public
//  License for more details.
//
//  This project is sponsored by the Office of Naval Research, One Liberty
//  Center, 875 N. Randolph Street, Arlington, VA 22203 under contract #
//  N68335-17-C-0700.  The content of the information does not necessarily
//  reflect the position or policy of the Government and no official
//  endorsement should be inferred.
//
//===----------------------------------------------------------------------===//
#include <algorithm>
#include <string>

#include "X64Decoder.h"

std::optional<X64Decoder::Instruction> X64Decoder::disasm(const uint8_t* Bytes, uint64_t Size,
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

std::optional<X64Decoder::Instruction> X64Decoder::build(const cs_insn& CsInstruction)
{
    cs_x86& Details = CsInstruction.detail->x86;
    auto [Prefix, Name] = splitMnemonic(CsInstruction);
    std::vector<uint64_t> OpCodes;

    if(Name != "NOP")
    {
        int OpCount = Details.op_count;
        for(int i = 0; i < OpCount; i++)
        {
            // Load capstone operand.
            cs_x86_op& CsOp = Details.operands[i];

            // Build operand for datalog fact.
            std::optional<X64Decoder::Operand> Op = build(CsOp);
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
    uint8_t Imm(Details.encoding.imm_offset), Disp(Details.encoding.disp_offset);
    return X64Decoder::Instruction{Addr, Size, Prefix, Name, OpCodes, Imm, Disp};
}

std::tuple<std::string, std::string> X64Decoder::splitMnemonic(const cs_insn& CsInstruction)
{
    std::string PrefixName = uppercase(CsInstruction.mnemonic);
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

std::optional<X64Decoder::Operand> X64Decoder::build(const cs_x86_op& CsOp)
{
    auto registerName = [this](uint64_t Reg) {
        return (Reg == X86_REG_INVALID) ? "NONE" : uppercase(cs_reg_name(CsHandle, Reg));
    };

    switch(CsOp.type)
    {
        case X86_OP_REG:
            return registerName(CsOp.reg);
        case X86_OP_IMM:
            return CsOp.imm;
        case X86_OP_MEM:
        {
            IndirectOp I = {registerName(CsOp.mem.segment),
                            registerName(CsOp.mem.base),
                            registerName(CsOp.mem.index),
                            CsOp.mem.scale,
                            CsOp.mem.disp,
                            CsOp.size * 8};
            return I;
        }
        case X86_OP_INVALID:
        default:
            break;
    }
    return std::nullopt;
}
