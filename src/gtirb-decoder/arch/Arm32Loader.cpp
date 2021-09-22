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
    Program.insert("op_register_bitfield", Operands.reg_bitfields());
}

void Arm32Loader::load(const gtirb::ByteInterval& ByteInterval, Arm32Facts& Facts)
{
    // NOTE: AArch32 (ARMv8-A) is backward compatible to ARMv7-A.
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

std::optional<relations::Instruction> Arm32Loader::build(Arm32Facts& Facts,
                                                         const cs_insn& CsInstruction)
{
    const cs_arm& Details = CsInstruction.detail->arm;
    std::string Name = uppercase(CsInstruction.mnemonic);
    if(auto index = Name.rfind(".W"); index != std::string::npos)
        Name = Name.substr(0, index);

    std::vector<uint64_t> OpCodes;

    auto registerName = [this](uint64_t Reg) {
        return (Reg == ARM_REG_INVALID) ? "NONE" : uppercase(cs_reg_name(*CsHandle, Reg));
    };

    auto regBitFieldInitialIndex = [](const std::string& Str) {
        std::string OpCode = Str.substr(0, 3);
        if(OpCode == "LDM" or OpCode == "STM")
            return 1;
        if(OpCode == "POP")
            return 0;

        OpCode = Str.substr(0, 4);
        if(OpCode == "PUSH")
            return 0;
        if(OpCode == "VSTM" or OpCode == "VLDM")
            return 1;

        return -1;
    };

    int OpCount = Details.op_count;
    if(regBitFieldInitialIndex(Name) != -1)
    {
        std::vector<std::string> RegBitFields;
        for(int i = 0; i < OpCount; i++)
        {
            // Load capstone operand.
            const cs_arm_op& CsOp = Details.operands[i];

            if(i < regBitFieldInitialIndex(Name))
            {
                std::optional<relations::Operand> Op = build(CsOp);
                // Build operand for datalog fact.
                if(!Op)
                {
                    return std::nullopt;
                }
                // Add operand to the operands table.
                uint64_t OpIndex = Facts.Operands.add(*Op);
                OpCodes.push_back(OpIndex);
            }
            else
            {
                RegBitFields.push_back(registerName(CsOp.reg));
            }
        }
        // Add reg_bitfield to the table.
        uint64_t OpIndex = Facts.Operands.add(RegBitFields);
        OpCodes.push_back(OpIndex);
    }
    else if(Name != "NOP")
    {
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
            uint64_t OpIndex = Facts.Operands.add(*Op);
            OpCodes.push_back(OpIndex);
        }
    }

    // Put the destination operand at the end of the operand list.
    if(!OpCodes.empty())
    {
        std::rotate(OpCodes.begin(), OpCodes.begin() + 1, OpCodes.end());
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
