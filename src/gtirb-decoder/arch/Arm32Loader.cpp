//===- Arm32Loader.h --------------------------------------------*- C++ -*-===//
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
#include "Arm32Loader.h"

#include <algorithm>
#include <string>
#include <vector>

void Arm32Loader::insert(const Arm32Facts& Facts, DatalogProgram& Program)
{
    auto& [Instructions, Operands] = Facts;
    Program.insert("instruction", Instructions.instructions());
    Program.insert("invalid_op_code", Instructions.invalid());
    Program.insert("op_immediate", Operands.imm());
    Program.insert("op_regdirect", Operands.reg());
    Program.insert("op_indirect", Operands.indirect());
    Program.insert("operand_list", Instructions.operand_lists());
}

void Arm32Loader::load(const gtirb::ByteInterval& ByteInterval, Arm32Facts& Facts)
{
    cs_option(*CsHandle, CS_OPT_MODE, CS_MODE_ARM | CS_MODE_V8);
    InstructionSize = 4;
    load(ByteInterval, Facts, false);

    cs_option(*CsHandle, CS_OPT_MODE, CS_MODE_THUMB | CS_MODE_V8);
    InstructionSize = 2;
    load(ByteInterval, Facts, true);
}

void Arm32Loader::load(const gtirb::ByteInterval& ByteInterval, Arm32Facts& Facts, bool Thumb)
{
    assert(ByteInterval.getAddress() && "ByteInterval is non-addressable.");

    uint64_t Addr = static_cast<uint64_t>(*ByteInterval.getAddress());
    uint64_t Size = ByteInterval.getInitializedSize();
    auto Data = ByteInterval.rawBytes<const uint8_t>();

    // Thumb instruction candidates are distinguished by the least significant bit (1).
    if(Thumb)
    {
        Addr++;
    }

    while(Size >= InstructionSize)
    {
        decode(Facts, Data, Size, Addr);
        Addr += InstructionSize;
        Data += InstructionSize;
        Size -= InstructionSize;
    }
}

void Arm32Loader::decode(Arm32Facts& Facts, const uint8_t* Bytes, uint64_t Size, uint64_t Addr)
{
    // Decode instruction with Capstone.
    cs_insn* CsInsn;
    size_t Count = cs_disasm(*CsHandle, Bytes, Size, Addr, 1, &CsInsn);

    // Build datalog instruction facts from Capstone instruction.
    std::optional<relations::Instruction> Instruction;
    std::optional<relations::OperandList> OperandList;
    if(Count > 0)
    {
        auto p = build(Facts, *CsInsn);
        Instruction = p.first;
        OperandList = p.second;
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

    if(OperandList)
    {
        // Add the operand list to the instruction facts table.
        Facts.Instructions.add(*OperandList);
    }

    cs_free(CsInsn, Count);
}

std::pair<std::optional<relations::Instruction>, std::optional<relations::OperandList>>
Arm32Loader::build(Arm32Facts& Facts, const cs_insn& CsInstruction)
{
    const cs_arm& Details = CsInstruction.detail->arm;
    std::string Name = uppercase(CsInstruction.mnemonic);
    std::vector<uint64_t> OpCodes4;    // The first 4 operands
    std::vector<uint64_t> OpCodesRest; // The rest operands

    if(Name != "NOP")
    {
        int OpCount = Details.op_count;
        for(int i = 0; i < OpCount; i++)
        {
            // Load capstone operand.
            const cs_arm_op& CsOp = Details.operands[i];

            // Build operand for datalog fact.
            std::optional<relations::Operand> Op = build(CsOp);
            if(!Op)
            {
                return std::make_pair(std::nullopt, std::nullopt);
            }

            // Add operand to the operands table.
            uint64_t OpIndex = Facts.Operands.add(*Op);
            if(i < 4)
                OpCodes4.push_back(OpIndex);
            else
            {
                OpCodesRest.push_back(OpIndex);
            }
        }
        // Put the destination operand at the end of the operand list.
        if(OpCount > 0)
        {
            if(OpCount <= 4)
            {
                std::rotate(OpCodes4.begin(), OpCodes4.begin() + 1, OpCodes4.end());
            }
            else
            {
                // Left-rotate by 1 the concatenation of the two vectors
                uint64_t first1 = *OpCodes4.begin();
                uint64_t first2 = *OpCodesRest.begin();

                OpCodes4.erase(OpCodes4.begin());
                OpCodes4.push_back(first2);

                OpCodesRest.erase(OpCodesRest.begin());
                OpCodesRest.push_back(first1);
            }
        }
    }

    gtirb::Addr Addr(CsInstruction.address);
    uint64_t Size(CsInstruction.size);
    return std::make_pair(relations::Instruction{Addr, Size, "", Name, OpCodes4, 0, 0},
                          relations::OperandList{Addr, OpCodesRest});
}

std::optional<relations::Operand> Arm32Loader::build(const cs_arm_op& CsOp)
{
    using namespace relations;

    auto registerName = [this](uint64_t Reg) {
        return (Reg == ARM_REG_INVALID) ? "NONE" : uppercase(cs_reg_name(*CsHandle, Reg));
    };

    switch(CsOp.type)
    {
        case ARM_OP_REG:
            return RegOp{registerName(CsOp.reg)};
        case ARM_OP_IMM:
            return ImmOp{CsOp.imm};
        case ARM_OP_MEM:
        {
            IndirectOp I = {registerName(ARM_REG_INVALID),
                            registerName(CsOp.mem.base),
                            registerName(CsOp.mem.index),
                            CsOp.mem.scale * (1 << CsOp.mem.lshift),
                            CsOp.mem.disp,
                            32};
            return I;
        }
        // TODO:
        case ARM_OP_CIMM: ///< C-Immediate (coprocessor registers)
        case ARM_OP_PIMM: ///< P-Immediate (coprocessor registers)
            return ImmOp{CsOp.imm};
        case ARM_OP_SYSREG: ///< MSR/MRS special register operand
            return RegOp{"MSR"};
        case ARM_OP_FP:
            std::cerr << "unhandled ARM operand: fp (ARM_OP_FP)\n";
        case ARM_OP_SETEND: ///< operand for SETEND instruction
            std::cerr << "unhandled ARM operand: setend (ARM_OP_SETEND)\n";
        case ARM_OP_INVALID:
        default:
            break;
    }

    return std::nullopt;
}
