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
#include <algorithm>
#include <string>
#include <vector>

#include "Arm32Loader.h"

void Arm32Loader::insert(const Arm32Facts& Facts, DatalogProgram& Program)
{
    Program.insert("instruction_complete", Facts.instructions());
    Program.insert("invalid_op_code", Facts.invalid());
    Program.insert("op_immediate", Facts.imm());
    Program.insert("op_regdirect", Facts.reg());
    Program.insert("op_indirect", Facts.indirect());
}

void Arm32Loader::load(const gtirb::ByteInterval& ByteInterval, Arm32Facts& Facts)
{
    cs_option(*CsHandle, CS_OPT_MODE, CS_MODE_ARM);
    load(ByteInterval, Facts, false);

    cs_option(*CsHandle, CS_OPT_MODE, CS_MODE_THUMB);
    load(ByteInterval, Facts, true);
}

void Arm32Loader::load(const gtirb::ByteInterval& ByteInterval, Arm32Facts& Facts, bool Thumb)
{
    assert(ByteInterval.getAddress() && "ByteInterval is non-addressable.");

    uint64_t Addr = static_cast<uint64_t>(*ByteInterval.getAddress());
    uint64_t Size = ByteInterval.getInitializedSize();
    auto Data = ByteInterval.rawBytes<const uint8_t>();

    if(Thumb)
    {
        InstructionSize = 2;
        Addr++;
    }
    else
    {
        InstructionSize = 4;
    }

    while(Size >= InstructionSize)
    {
        Increment = InstructionSize;
        decode(Facts, Data, Size, Addr);
        Addr += Increment;
        Data += Increment;
        Size -= Increment;
    }
}

void Arm32Loader::decode(Arm32Facts& Facts, const uint8_t* Bytes, uint64_t Size, uint64_t Addr)
{
    // Decode instruction with Capstone.
    cs_insn* CsInsn;
    size_t Count = cs_disasm(*CsHandle, Bytes, Size, Addr, 1, &CsInsn);

    // Build datalog instruction facts from Capstone instruction.
    std::optional<relations::Instruction> Instruction;
    if(Count > 0)
    {
        Instruction = build(Facts, *CsInsn);
        Increment = CsInsn->size;
    }

    if(Instruction)
    {
        // Add the instruction to the facts table.
        Facts.add(*Instruction);
    }
    else
    {
        // Add address to list of invalid instruction locations.
        Facts.invalid(gtirb::Addr(Addr));
    }

    cs_free(CsInsn, Count);
}

std::optional<relations::Instruction> Arm32Loader::build(Arm32Facts& Facts,
                                                         const cs_insn& CsInstruction)
{
    const cs_arm& Details = CsInstruction.detail->arm;
    std::string Name = uppercase(CsInstruction.mnemonic);
    std::vector<uint64_t> OpCodes;

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
                return std::nullopt;
            }

            // Add operand to the operands table.
            uint64_t OpIndex = Facts.add(*Op);
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