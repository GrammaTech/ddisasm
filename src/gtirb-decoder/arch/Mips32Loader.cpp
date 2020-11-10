//===- Mips32Loader.cpp -------------------------------------------*- C++ -*-===//
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
#include <vector>

#include "Mips32Loader.h"

void Mips32Loader::insert(const Mips32Facts& Facts, DatalogProgram& Program)
{
    auto& [Instructions, Operands] = Facts;
    Program.insert("instruction", Instructions.instructions());
    Program.insert("invalid_op_code", Instructions.invalid());
    Program.insert("op_immediate", Operands.imm());
    Program.insert("op_regdirect", Operands.reg());
    Program.insert("op_indirect", Operands.indirect());
}

void Mips32Loader::decode(Mips32Facts& Facts, const uint8_t* Bytes, uint64_t /* Size */,
                          uint64_t Addr)
{
    // Decode instruction with Capstone.
    cs_insn* CsInsn;
    const uint8_t BigEndianBytes[] = {Bytes[3], Bytes[2], Bytes[1], Bytes[0]};
    size_t Count = cs_disasm(*CsHandle, BigEndianBytes, 4, Addr, 1, &CsInsn);

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

std::optional<relations::Instruction> Mips32Loader::build(Mips32Facts& Facts,
                                                          const cs_insn& CsInstruction)
{
    const cs_mips& Details = CsInstruction.detail->mips;
    std::string Name = uppercase(CsInstruction.mnemonic);
    std::vector<uint64_t> OpCodes;

    if(Name != "NOP")
    {
        int OpCount = Details.op_count;
        for(int i = 0; i < OpCount; i++)
        {
            // Load capstone operand.
            const cs_mips_op& CsOp = Details.operands[i];

            // Build operand for datalog fact.
            std::optional<relations::Operand> Op = build(CsOp);
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

std::optional<relations::Operand> Mips32Loader::build(const cs_mips_op& CsOp)
{
    auto registerName = [this](unsigned int Reg) {
        return (Reg == MIPS_REG_INVALID) ? "NONE" : uppercase(cs_reg_name(*CsHandle, Reg));
    };

    switch(CsOp.type)
    {
        case MIPS_OP_REG:
            return registerName(CsOp.reg);
        case MIPS_OP_IMM:
            return CsOp.imm;
        case X86_OP_MEM:
        {
            relations::IndirectOp I = {registerName(MIPS_REG_INVALID),
                                       registerName(CsOp.mem.base),
                                       registerName(MIPS_REG_INVALID),
                                       1,
                                       CsOp.mem.disp,
                                       32};
            return I;
        }
        case MIPS_OP_INVALID:
        default:
            break;
    }
    return std::nullopt;
}
