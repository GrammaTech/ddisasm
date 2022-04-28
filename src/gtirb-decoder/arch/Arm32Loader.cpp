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
    Program.insert("instruction_writeback", Instructions.writeback());
    Program.insert("invalid_op_code", Instructions.invalid());
    Program.insert("op_shifted", Instructions.shiftedOps());
    Program.insert("op_shifted_w_reg", Instructions.shiftedWithRegOps());
    Program.insert("op_immediate", Operands.imm());
    Program.insert("op_regdirect", Operands.reg());
    Program.insert("op_indirect", Operands.indirect());
    Program.insert("op_special", Operands.special());
    Program.insert("op_register_bitfield", Operands.reg_bitfields());
}

void Arm32Loader::load(const gtirb::Module& Module, const gtirb::ByteInterval& ByteInterval,
                       Arm32Facts& Facts)
{
    // NOTE: AArch32 (ARMv8-A) is backward compatible to ARMv7-A.
    cs_option(*CsHandle, CS_OPT_MODE, CS_MODE_ARM | CS_MODE_V8);
    InstructionSize = 4;
    load(ByteInterval, Facts, false);

    // For Thumb, check if the arch type is available.
    // For Cortex-M, add CS_MODE_MCLASS to the cs option.
    Mclass = false;
    const auto& Sections = Module.findSections(".ARM.attributes");
    if(!Sections.empty())
    {
        const auto& Section = *Sections.begin();
        for(const auto& ByteInterval : Section.byte_intervals())
        {
            const char* RawChars = ByteInterval.rawBytes<const char>();
            // Remove zeros
            std::vector<char> Chars;
            for(size_t I = 0; I < ByteInterval.getInitializedSize(); ++I)
            {
                if(RawChars[I] != 0)
                    Chars.push_back(RawChars[I]);
            }
            std::string SectStr(Chars.begin(), Chars.end());
            if(SectStr.find("Cortex-M7") != std::string::npos)
            {
                Mclass = true;
                break;
            }
        }
        ArchtypeFromElf = true;
    }

    if(Mclass)
    {
        cs_option(*CsHandle, CS_OPT_MODE, CS_MODE_THUMB | CS_MODE_V8 | CS_MODE_MCLASS);
    }
    else
    {
        cs_option(*CsHandle, CS_OPT_MODE, CS_MODE_THUMB | CS_MODE_V8);
    }
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
        decode(Facts, Data, Size, Addr, Thumb);
        Addr += InstructionSize;
        Data += InstructionSize;
        Size -= InstructionSize;
    }
}

void Arm32Loader::decode(Arm32Facts& Facts, const uint8_t* Bytes, uint64_t Size, uint64_t Addr,
                         bool Thumb)
{
    size_t CsModes[2];
    size_t CsModeCount = 1;
    if(Thumb)
    {
        if(ArchtypeFromElf)
        {
            if(Mclass)
            {
                CsModes[0] = (CS_MODE_THUMB | CS_MODE_V8 | CS_MODE_MCLASS);
            }
            else
            {
                CsModes[0] = (CS_MODE_THUMB | CS_MODE_V8);
            }
        }
        else
        {
            if(Mclass)
            {
                CsModes[1] = (CS_MODE_THUMB | CS_MODE_V8 | CS_MODE_MCLASS);
                CsModes[0] = (CS_MODE_THUMB | CS_MODE_V8);
            }
            else
            {
                CsModes[0] = (CS_MODE_THUMB | CS_MODE_V8);
                CsModes[1] = (CS_MODE_THUMB | CS_MODE_V8 | CS_MODE_MCLASS);
            }
            CsModeCount = 2;
        }
    }
    else
    {
        CsModes[0] = (CS_MODE_ARM | CS_MODE_V8);
    }

    std::unique_ptr<cs_insn, std::function<void(cs_insn*)>> InsnPtr;
    size_t InsnCount = 0;

    // NOTE: If the ARM CPU profile is not known, we may have to switch modes
    // to successfully decode all instructions.
    // Thumb2 MRS and MSR instructions support a larger set of `<spec_reg>` on
    // M-profile devices, so they do not decode without CS_MODE_MCLASS.
    // The Thumb 'blx label' instruction does not decode with CS_MODE_MCLASS,
    // because it is not a supported instruction on M-profile devices.
    //
    // This loop is to try out multiple CS modes to see if decoding succeeds.
    // Currently, this is done only when the arch type info is not available.
    bool InstAdded = false;
    for(size_t I = 0; I < CsModeCount; I++)
    {
        // Decode instruction with Capstone.
        cs_insn* Insn;
        cs_option(*CsHandle, CS_OPT_DETAIL, CS_OPT_ON);
        cs_option(*CsHandle, CS_OPT_MODE, CsModes[I]);
        size_t TmpCount = cs_disasm(*CsHandle, Bytes, Size, Addr, 1, &Insn);

        // Exception-safe cleanup of instructions
        std::unique_ptr<cs_insn, std::function<void(cs_insn*)>> TmpInsnPtr(
            Insn, [TmpCount](cs_insn* Instr) { cs_free(Instr, TmpCount); });

        Arm32Facts TempFacts;
        InstAdded = false;
        if(TmpCount > 0)
        {
            bool Update = false;
            InstAdded = build(TempFacts, Insn[TmpCount - 1], Update);
        }

        if(InstAdded)
        {
            InsnPtr = std::move(TmpInsnPtr);
            InsnCount = TmpCount;
            if(CsModes[I] & CS_MODE_MCLASS != 0)
            {
                Mclass = true;
            }
            break;
        }
    }

    if(InstAdded)
    {
        // Build datalog instruction facts from Capstone instruction.
        bool Update = true;
        build(Facts, (&(*InsnPtr))[InsnCount - 1], Update);
    }
    else
    {
        // Add address to list of invalid instruction locations.
        Facts.Instructions.invalid(gtirb::Addr(Addr));
    }
}

bool Arm32Loader::build(Arm32Facts& Facts, const cs_insn& CsInstruction, bool Update)
{
    const cs_arm& Details = CsInstruction.detail->arm;
    std::string Name = uppercase(CsInstruction.mnemonic);
    gtirb::Addr Addr(CsInstruction.address);
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
                std::optional<relations::Operand> Op = build(CsInstruction, CsOp);
                // Build operand for datalog fact.
                if(!Op)
                {
                    return false;
                }
                if(Update)
                {
                    // Add operand to the operands table.
                    uint64_t OpIndex = Facts.Operands.add(*Op);
                    OpCodes.push_back(OpIndex);
                }
            }
            else
            {
                RegBitFields.push_back(registerName(CsOp.reg));
            }
        }
        if(Update)
        {
            // Add reg_bitfield to the table.
            uint64_t OpIndex = Facts.Operands.add(RegBitFields);
            OpCodes.push_back(OpIndex);
        }
    }
    else if(Name != "NOP")
    {
        for(int i = 0; i < OpCount; i++)
        {
            // Load capstone operand.
            const cs_arm_op& CsOp = Details.operands[i];

            // Build operand for datalog fact.
            std::optional<relations::Operand> Op = build(CsInstruction, CsOp);
            if(!Op)
            {
                return false;
            }

            if(Update)
            {
                // Add operand to the operands table.
                uint64_t OpIndex = Facts.Operands.add(*Op);
                OpCodes.push_back(OpIndex);
            }

            // Populate shift metadata if present.
            if(CsOp.type == ARM_OP_REG && CsOp.shift.value != 0)
            {
                std::string ShiftType;
                switch(CsOp.shift.type)
                {
                    case ARM_SFT_ASR:
                    case ARM_SFT_ASR_REG:
                        ShiftType = "ASR";
                        break;
                    case ARM_SFT_LSL:
                    case ARM_SFT_LSL_REG:
                        ShiftType = "LSL";
                        break;
                    case ARM_SFT_LSR:
                    case ARM_SFT_LSR_REG:
                        ShiftType = "LSR";
                        break;
                    case ARM_SFT_ROR:
                    case ARM_SFT_ROR_REG:
                        ShiftType = "ROR";
                        break;
                    case ARM_SFT_RRX:
                    case ARM_SFT_RRX_REG:
                        ShiftType = "RRX";
                        break;
                    case ARM_SFT_INVALID:
                        std::cerr << "WARNING: instruction has a non-zero invalid shift at " << Addr
                                  << "\n";
                        return false;
                }
                if(Update)
                {
                    if(CsOp.shift.value > 32)
                    {
                        Facts.Instructions.shiftedWithRegOp(
                            relations::ShiftedWithRegOp{Addr, static_cast<uint8_t>(i + 1),
                                                        registerName(CsOp.shift.value), ShiftType});
                    }
                    else
                    {
                        Facts.Instructions.shiftedOp(relations::ShiftedOp{
                            Addr, static_cast<uint8_t>(i + 1),
                            static_cast<uint8_t>(CsOp.shift.value), ShiftType});
                    }
                }
            }
        }
    }

    // Put the destination operand at the end of the operand list.
    if(!OpCodes.empty())
    {
        std::rotate(OpCodes.begin(), OpCodes.begin() + 1, OpCodes.end());
    }

    if(Update)
    {
        uint64_t Size(CsInstruction.size);

        Facts.Instructions.add(relations::Instruction{Addr, Size, "", Name, OpCodes, 0, 0});
        if(Details.writeback)
        {
            Facts.Instructions.writeback(relations::InstructionWriteback{Addr});
        }
    }
    return true;
}

std::optional<relations::Operand> Arm32Loader::build(const cs_insn& CsInsn, const cs_arm_op& CsOp)
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
            // CsOp.mem.lshift seems to be incorrect for some instructions,
            // see: https://github.com/capstone-engine/capstone/issues/1848
            // TODO: LDR instructions support ASR, LSL, LSR, ROR, and RRX shifts.
            // Only LSL can be represented as a multiplier.
            if(CsOp.shift.value && CsOp.shift.type != ARM_SFT_LSL)
                std::cerr << "WARNING: Unhandled shift type in mem operand ("
                          << "address=0x" << std::hex << CsInsn.address << std::dec << ", "
                          << "value=0x" << std::hex << CsOp.shift.value << std::dec << ", "
                          << "type=" << CsOp.shift.type << ")\n";

            IndirectOp I = {registerName(ARM_REG_INVALID),
                            registerName(CsOp.mem.base),
                            registerName(CsOp.mem.index),
                            CsOp.mem.scale * (1 << CsOp.shift.value),
                            CsOp.mem.disp,
                            32};
            return I;
        }
        case ARM_OP_CIMM: ///< C-Immediate (coprocessor registers)
        case ARM_OP_PIMM: ///< P-Immediate (coprocessor registers)
            return ImmOp{CsOp.imm};
        case ARM_OP_SYSREG: ///< MSR/MRS special register operand
            return RegOp{"MSR"};
        case ARM_OP_FP:
            return FPImmOp{CsOp.fp};
        case ARM_OP_SETEND: ///< operand for SETEND instruction
            switch(CsOp.setend)
            {
                case ARM_SETEND_BE:
                    return SpecialOp{"setend", "be"};
                case ARM_SETEND_LE:
                    return SpecialOp{"setend", "le"};
                default:
                    break;
            }
            break;
        case ARM_OP_INVALID:
        default:
            break;
    }

    return std::nullopt;
}
