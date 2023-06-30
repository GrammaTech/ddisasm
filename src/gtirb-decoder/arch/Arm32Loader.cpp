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

const std::set<std::string> Versions = {
    "Pre_v4", "v4",        "v4T",       "v5T",         "v5TE",  "v5TEJ", "v6",
    "v6KZ",   "v6K",       "v7",        "v6_M",        "v6S_M", "v7E_M", "v8_A",
    "v8_R",   "v8_M_Base", "v8_M_Main", "v8_1_M_Main", "v9_A",
};
const std::set<std::string> VNoThumb = {"Pre_v4", "v4"};

void Arm32Loader::initCsModes(const gtirb::Module& Module)
{
    bool ProfileInArchInfo = false;
    std::string Profile;
    bool VersionSupportsThumb = true;
    auto* ArchInfo = Module.getAuxData<gtirb::schema::ArchInfo>();
    if(ArchInfo)
    {
        auto ProfileIt = ArchInfo->find("Profile");
        if(ProfileIt != ArchInfo->end())
        {
            ProfileInArchInfo = true;
            Profile = ProfileIt->second;
        }

        auto ArchIt = ArchInfo->find("Arch");
        if(ArchIt != ArchInfo->end() && (VNoThumb.count(ArchIt->second) > 0))
        {
            VersionSupportsThumb = false;
        }
    }

    // Execution modes are ARM or Thumb.
    std::vector<size_t> ExecutionModes;
    if(!ProfileInArchInfo || Profile != "Microcontroller")
    {
        // The ARM Microcontroller profile does not support ARM mode.
        ExecutionModes.push_back(CS_MODE_ARM);
    }
    if(VersionSupportsThumb)
    {
        ExecutionModes.push_back(CS_MODE_THUMB);
    }

    for(size_t ExecutionMode : ExecutionModes)
    {
        // Modifiers: CS_MODE_MCLASS
        std::vector<size_t> Modifiers;
        if(ExecutionMode == CS_MODE_ARM)
        {
            Modifiers.push_back(0);
        }
        else
        {
            if(ProfileInArchInfo)
            {
                // Only use the known profile
                Modifiers.push_back(Profile == "Microcontroller" ? CS_MODE_MCLASS : 0);
            }
            else
            {
                // If the ARM CPU profile is not known, we may have to toggle
                // CS_MODE_MCLASS to successfully decode all instructions.
                // Thumb2 MRS and MSR instructions support a larger set of `<spec_reg>` on
                // M-profile devices, so they do not decode without CS_MODE_MCLASS.
                // The Thumb 'blx label' instruction does not decode with CS_MODE_MCLASS,
                // because it is not a supported instruction on M-profile devices.
                Modifiers.push_back(0);
                Modifiers.push_back(CS_MODE_MCLASS);
            }
        }

        for(size_t Modifier : Modifiers)
        {
            // Always try both with and without CS_MODE_V8.
            // We'd like to use the version from ArchInfo to decide this when
            // present, but capstone seems to be missing some pre-V8
            // instructions without CS_MODE_V8. For example, "vcvt.f64.u32"
            // (40 0b f8 ee) is a valid Advanced SIMD instruction according to
            // "ARM Architecture Reference Manual ARMv7-A and ARMv7-R edition"
            // and has been observed in binaries with v7 defined in arch info,
            // but capstone only decodes it successfully with CS_MODE_V8.
            // CS_MODE_V8 is also not a strict superset of v7; the instruction
            // "ldcl p1, c0, [r0], #8" (02 01 f0 ec) is valid only without
            // CS_MODE_V8.
            CsModes[ExecutionMode].push_back(ExecutionMode | Modifier | CS_MODE_V8);
            CsModes[ExecutionMode].push_back(ExecutionMode | Modifier);
        }
    }
}

void Arm32Loader::load(const gtirb::Module& Module, const gtirb::ByteInterval& ByteInterval,
                       BinaryFacts& Facts)
{
    for(auto&& [ExecutionMode, CurrentCsModes] : CsModes)
    {
        load(ByteInterval, Facts, ExecutionMode, CurrentCsModes);
    }
}

void Arm32Loader::load(const gtirb::ByteInterval& ByteInterval, BinaryFacts& Facts,
                       size_t ExecutionMode, const std::vector<size_t>& CsModes)
{
    assert(ByteInterval.getAddress() && "ByteInterval is non-addressable.");

    uint64_t Addr = static_cast<uint64_t>(*ByteInterval.getAddress());
    uint64_t Size = ByteInterval.getInitializedSize();
    auto Data = ByteInterval.rawBytes<const uint8_t>();

    // Thumb instruction candidates are distinguished by the least significant bit (1).
    if(ExecutionMode == CS_MODE_ARM)
    {
        MinInstructionSize = 4;
    }
    else
    {
        MinInstructionSize = 2;
        Addr++;
    }

    while(Size >= MinInstructionSize)
    {
        decode(Facts, Data, Size, Addr, CsModes);
        Addr += MinInstructionSize;
        Data += MinInstructionSize;
        Size -= MinInstructionSize;
    }
}

void Arm32Loader::decode(BinaryFacts& Facts, const uint8_t* Bytes, uint64_t Size, uint64_t Addr,
                         const std::vector<size_t>& CsModes)
{
    size_t InsnCount = 0;

    // This loop is to try out multiple CS modes until decoding succeeds.
    // This generates a superset of all decoding options, assuming the same
    // bytes do not decode to two different results on different modes.
    bool Success = false;
    OpndFactsT OpndFacts;
    std::unique_ptr<cs_insn, std::function<void(cs_insn*)>> Insn;
    for(size_t CsMode : CsModes)
    {
        cs_option(*CsHandle, CS_OPT_MODE, CsMode);
        cs_insn* TmpInsnRaw = nullptr;
        size_t Count = cs_disasm(*CsHandle, Bytes, Size, Addr, 1, &TmpInsnRaw);
        Success = Count > 0;
        std::unique_ptr<cs_insn, std::function<void(cs_insn*)>> TmpInsn(
            TmpInsnRaw, [Count](cs_insn* Instr) { cs_free(Instr, Count); });

        if(Success)
        {
            OpndFacts.clear();
            Success = collectOpndFacts(OpndFacts, *TmpInsnRaw);
            Insn = std::move(TmpInsn);
            if(Success)
            {
                break;
            }
        }
    }

    if(Success)
    {
        // Build datalog instruction facts from Capstone instruction.
        build(Facts, *Insn, OpndFacts);
        loadRegisterAccesses(Facts, Addr, *Insn);

        if((*Insn).detail->arm.update_flags)
        {
            // Capstone bug: for some instructions, "CPSR" is missing from regs_write even when
            // update_flags is set.
            Facts.Instructions.registerAccess(
                relations::RegisterAccess{gtirb::Addr(Addr), "W", "CPSR"});
        }
    }
    else
    {
        // Add address to list of invalid instruction locations.
        Facts.Instructions.invalid(gtirb::Addr(Addr));
    }
}

static std::string armCc2String(arm_cc CC)
{
    std::string OpCC = "";
    switch(CC)
    {
        case ARM_CC_INVALID:
            assert(!"Unexpected condition code for IT instruction");
        case ARM_CC_EQ:
            OpCC = "EQ";
            break;
        case ARM_CC_NE:
            OpCC = "NE";
            break;
        case ARM_CC_HS:
            OpCC = "HS";
            break;
        case ARM_CC_LO:
            OpCC = "LO";
            break;
        case ARM_CC_MI:
            OpCC = "MI";
            break;
        case ARM_CC_PL:
            OpCC = "PL";
            break;
        case ARM_CC_VS:
            OpCC = "VS";
            break;
        case ARM_CC_VC:
            OpCC = "VC";
            break;
        case ARM_CC_HI:
            OpCC = "HI";
            break;
        case ARM_CC_LS:
            OpCC = "LS";
            break;
        case ARM_CC_GE:
            OpCC = "GE";
            break;
        case ARM_CC_LT:
            OpCC = "LT";
            break;
        case ARM_CC_GT:
            OpCC = "GT";
            break;
        case ARM_CC_LE:
            OpCC = "LE";
            break;
        case ARM_CC_AL:
            OpCC = "AL";
            break;
    }
    assert(OpCC != "");
    return OpCC;
}

bool Arm32Loader::collectOpndFacts(OpndFactsT& OpndFacts, const cs_insn& CsInst)
{
    const cs_arm& Details = CsInst.detail->arm;
    std::string Name = uppercase(CsInst.mnemonic);
    gtirb::Addr Addr(CsInst.address);
    if(auto index = Name.rfind(".W"); index != std::string::npos)
        Name = Name.substr(0, index);

    auto registerName = [this](uint64_t Reg) {
        return (Reg == ARM_REG_INVALID) ? "NONE" : uppercase(cs_reg_name(*CsHandle, Reg));
    };

    static std::set<arm_insn> LdmStm = {
        ARM_INS_LDM,     ARM_INS_LDMDA,   ARM_INS_LDMDB,  ARM_INS_LDMIB,
        ARM_INS_FLDMDBX, ARM_INS_FLDMIAX, ARM_INS_VLDMDB, ARM_INS_VLDMIA,
        ARM_INS_STM,     ARM_INS_STMDA,   ARM_INS_STMDB,  ARM_INS_STMIB,
        ARM_INS_FSTMDBX, ARM_INS_FSTMIAX, ARM_INS_VSTMDB, ARM_INS_VSTMIA};

    static std::set<arm_insn> PushPop = {ARM_INS_POP, ARM_INS_PUSH, ARM_INS_VPOP, ARM_INS_VPUSH};

    static std::set<arm_insn> VldVst = {ARM_INS_VLD1, ARM_INS_VLD2, ARM_INS_VLD3, ARM_INS_VLD4,
                                        ARM_INS_VST1, ARM_INS_VST2, ARM_INS_VST3, ARM_INS_VST4};

    auto regBitFieldInitialIndex = [](const cs_insn& Inst) {
        int RegBitVectorIndex = -1;
        if(LdmStm.find(static_cast<arm_insn>(Inst.id)) != LdmStm.end())
            RegBitVectorIndex = 1;
        if(PushPop.find(static_cast<arm_insn>(Inst.id)) != PushPop.end())
            RegBitVectorIndex = 0;
        if(VldVst.find(static_cast<arm_insn>(Inst.id)) != VldVst.end())
            RegBitVectorIndex = 0;
        return RegBitVectorIndex;
    };

    int OpCount = Details.op_count;
    int regBitFieldInitIdx = regBitFieldInitialIndex(CsInst);
    if(regBitFieldInitIdx != -1)
    {
        int i = 0;
        // Operands before bitfield.
        for(; i < regBitFieldInitIdx; i++)
        {
            const cs_arm_op& CsOp = Details.operands[i];
            std::optional<relations::Operand> Op = build(CsInst, CsOp);
            if(!Op)
            {
                return false;
            }
            OpndFacts.Operands.push_back(*Op);
        }
        // Bitfield operands
        std::vector<std::string> RegBitFields;
        for(; i < OpCount; i++)
        {
            const cs_arm_op& CsOp = Details.operands[i];
            // In case of VLDn or VSTn,
            // stop collecting reg fields once a memory indirect operand
            // is encountered.
            if(CsOp.type == ARM_OP_MEM)
            {
                assert(i != 0);
                break;
            }
            RegBitFields.push_back(registerName(CsOp.reg));
        }
        OpndFacts.Operands.push_back(RegBitFields);
        // Operands after bitfields
        for(; i < OpCount; i++)
        {
            const cs_arm_op& CsOp = Details.operands[i];
            std::optional<relations::Operand> Op = build(CsInst, CsOp);
            if(!Op)
            {
                return false;
            }
            OpndFacts.Operands.push_back(*Op);
        }
    }
    else if(CsInst.id == ARM_INS_IT)
    {
        // Capstone doesn't currently populate any operands for IT instructions.
        // Generate it based on the condition code.
        std::string OpCC = armCc2String(Details.cc);
        OpndFacts.Operands.push_back(relations::SpecialOp{"it", OpCC});
    }
    else if(Name != "NOP")
    {
        for(int i = 0; i < OpCount; i++)
        {
            // Load capstone operand.
            const cs_arm_op& CsOp = Details.operands[i];

            // Build operand for datalog fact.
            std::optional<relations::Operand> Op = build(CsInst, CsOp);
            if(!Op)
            {
                return false;
            }

            OpndFacts.Operands.push_back(*Op);

            // Populate shift metadata if present.
            if(CsOp.shift.type != ARM_SFT_INVALID && CsOp.shift.value != 0)
            {
                std::string ShiftType;
                bool IsRegShift = false;
                switch(CsOp.shift.type)
                {
                    case ARM_SFT_ASR_REG:
                        IsRegShift = true;
                    case ARM_SFT_ASR:
                        ShiftType = "ASR";
                        break;
                    case ARM_SFT_LSL_REG:
                        IsRegShift = true;
                    case ARM_SFT_LSL:
                        ShiftType = "LSL";
                        break;
                    case ARM_SFT_LSR_REG:
                        IsRegShift = true;
                    case ARM_SFT_LSR:
                        ShiftType = "LSR";
                        break;
                    case ARM_SFT_ROR_REG:
                        IsRegShift = true;
                    case ARM_SFT_ROR:
                        ShiftType = "ROR";
                        break;
                    case ARM_SFT_RRX_REG:
                        IsRegShift = true;
                    case ARM_SFT_RRX:
                        ShiftType = "RRX";
                        break;
                    case ARM_SFT_INVALID:
                        std::cerr << "WARNING: instruction has a non-zero invalid shift at " << Addr
                                  << "\n";
                        return false;
                }
                if(IsRegShift)
                {
                    OpndFacts.ShiftedWithRegOp =
                        relations::ShiftedWithRegOp{Addr, rotated_op_index(i + 1, OpCount),
                                                    registerName(CsOp.shift.value), ShiftType};
                }
                else
                {
                    OpndFacts.ShiftedOp =
                        relations::ShiftedOp{Addr, rotated_op_index(i + 1, OpCount),
                                             static_cast<uint8_t>(CsOp.shift.value), ShiftType};
                }
            }
        }
    }
    return true;
}

void Arm32Loader::build(BinaryFacts& Facts, const cs_insn& CsInstruction,
                        const OpndFactsT& OpndFacts)
{
    const cs_arm& Details = CsInstruction.detail->arm;
    std::string Name = uppercase(CsInstruction.mnemonic);
    gtirb::Addr Addr(CsInstruction.address);
    if(auto index = Name.rfind(".W"); index != std::string::npos)
        Name = Name.substr(0, index);

    std::vector<uint64_t> OpCodes;

    for(const auto& Operand : OpndFacts.Operands)
    {
        // Add operand to the operands table.
        uint64_t OpIndex = Facts.Operands.add(Operand);
        OpCodes.push_back(OpIndex);
    }

    // Put the destination operand at the end of the operand list.
    if(!OpCodes.empty())
    {
        std::rotate(OpCodes.begin(), OpCodes.begin() + 1, OpCodes.end());
    }

    uint64_t Size(CsInstruction.size);

    Facts.Instructions.add(relations::Instruction{Addr, Size, "", Name, OpCodes, 0, 0});

    if(Details.cc != ARM_CC_AL)
    {
        Facts.Instructions.conditionCode(
            relations::InstructionCondCode{Addr, armCc2String(Details.cc)});
    }
    if(Details.writeback)
    {
        Facts.Instructions.writeback(relations::InstructionWriteback{Addr});
    }

    if(OpndFacts.ShiftedWithRegOp)
    {
        Facts.Instructions.shiftedWithRegOp(*OpndFacts.ShiftedWithRegOp);
    }
    if(OpndFacts.ShiftedOp)
    {
        Facts.Instructions.shiftedOp(*OpndFacts.ShiftedOp);
    }
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
            // We translate LSL shifts into a Mult in op_indirect.
            // Other shifts must be verified with op_shifted.
            uint32_t LShiftMult = 1;
            if(CsOp.shift.type == ARM_SFT_LSL)
            {
                // CsOp.mem.lshift seems to be incorrect for some instructions,
                // see: https://github.com/capstone-engine/capstone/issues/1848
                // The lshift value can also be fetched via op.shift.value.
                // Therefore, we use op.shift.value here instead.
                LShiftMult = 1 << CsOp.shift.value;
            }

            // Capstone does not provide a way of accessing the size of
            // the memory reference.
            // Size should be 64 instead of 32 for double-word memory
            // reference: e.g., VLDR D0, [...]
            // TODO: (1) We could request capstone to be fixed, or (2) make
            // this function take the previous operand if any to infer the
            // reference size.
            // For now, datalog code needs to determine the size in other way:
            // e.g., look at the dest/src register for load/store instructions.
            IndirectOp I = {registerName(ARM_REG_INVALID),
                            registerName(CsOp.mem.base),
                            registerName(CsOp.mem.index),
                            CsOp.mem.scale * LShiftMult,
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

uint8_t Arm32Loader::operandCount(const cs_insn& CsInstruction)
{
    const cs_arm& Details = CsInstruction.detail->arm;
    return Details.op_count;
}

uint8_t Arm32Loader::operandAccess(const cs_insn& CsInstruction, uint64_t Index)
{
    const cs_arm& Details = CsInstruction.detail->arm;
    const cs_arm_op& op = Details.operands[Index];
    return op.access;
}
