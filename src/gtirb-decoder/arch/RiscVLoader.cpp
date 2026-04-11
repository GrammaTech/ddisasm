//===- RiscVLoader.cpp -------------------------------------------*- C++ -*-===//
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
#include "RiscVLoader.h"

#include <algorithm>
#include <string>
#include <vector>

bool RiscVLoader::isBranchJump(unsigned int InsnId) const
{
    switch(InsnId)
    {
        case RISCV_INS_JAL:
        case RISCV_INS_BEQ:
        case RISCV_INS_BNE:
        case RISCV_INS_BLT:
        case RISCV_INS_BGE:
        case RISCV_INS_BLTU:
        case RISCV_INS_BGEU:
        case RISCV_INS_C_BEQZ:
        case RISCV_INS_C_BNEZ:
        case RISCV_INS_C_J:
            return true;
        case RISCV_INS_C_JAL:
            // C.JAL only exists in RV32C, not RV64C.
            return HasCJal;
        default:
            return false;
    }
}

uint8_t RiscVLoader::compressedMemAccessSize(unsigned int InsnId) const
{
    // Compressed load/store instructions that use the non-default access size.
    // For RV32, default is 4 (word), so we list the 8-byte (double) variants.
    // For RV64, default is 8 (double), so we list the 4-byte (word) variants.
    // The two sets are complementary, so we check the same instruction IDs
    // and return the opposite of the default.
    switch(InsnId)
    {
        case RISCV_INS_C_LW:
        case RISCV_INS_C_SW:
        case RISCV_INS_C_LWSP:
        case RISCV_INS_C_SWSP:
        case RISCV_INS_C_FLW:
        case RISCV_INS_C_FSW:
        case RISCV_INS_C_FLWSP:
        case RISCV_INS_C_FSWSP:
            return 4;
        case RISCV_INS_C_LD:
        case RISCV_INS_C_SD:
        case RISCV_INS_C_LDSP:
        case RISCV_INS_C_SDSP:
        case RISCV_INS_C_FLD:
        case RISCV_INS_C_FSD:
        case RISCV_INS_C_FLDSP:
        case RISCV_INS_C_FSDSP:
            return 8;
        default:
            return DefaultCompressedMemSize;
    }
}

void RiscVLoader::decode(BinaryFacts& Facts, const uint8_t* Bytes, uint64_t Size, uint64_t Addr)
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

        // loadRegisterAccesses() is not called here since capstone does not
        // support register accesses on RISC-V.
    }
    else
    {
        // Add address to list of invalid instruction locations.
        Facts.Instructions.invalid(gtirb::Addr(Addr));
    }

    cs_free(CsInsn, Count);
}

std::optional<relations::Instruction> RiscVLoader::build(BinaryFacts& Facts,
                                                         const cs_insn& CsInstruction)
{
    const cs_riscv& Details = CsInstruction.detail->riscv;
    std::string Name = uppercase(CsInstruction.mnemonic);
    std::vector<uint64_t> OpCodes;

    // Determine if this is a branch/jump instruction.
    // Capstone returns raw PC-relative offsets for RISC-V branches/jumps,
    // unlike other architectures where it returns absolute targets.
    bool IsBranchJump = isBranchJump(CsInstruction.id);

    if(Name != "NOP" && Name != "C.NOP")
    {
        int OpCount = Details.op_count;

        // Capstone decodes compressed RISC-V load/store memory operands as
        // separate [REG, IMM, REG] instead of [REG, MEM]. Merge the IMM+REG
        // into a single IndirectOp so the datalog analysis (data_access) works
        // uniformly for both compressed and non-compressed instructions.
        bool IsCompressedMemOp = (OpCount == 3 && Details.operands[0].type == RISCV_OP_REG
                                  && Details.operands[1].type == RISCV_OP_IMM
                                  && Details.operands[2].type == RISCV_OP_REG);

        if(IsCompressedMemOp)
        {
            // operands[0] = dest/src reg, operands[1] = offset, operands[2] = base reg
            auto registerName = [this](unsigned int Reg) {
                return (Reg == RISCV_REG_INVALID) ? std::string("NONE")
                                                  : uppercase(cs_reg_name(*CsHandle, Reg));
            };

            // Build dest/src register operand.
            std::optional<relations::Operand> RegOp = build(Details.operands[0]);
            if(!RegOp)
                return std::nullopt;
            uint64_t RegOpIndex = Facts.Operands.add(*RegOp);

            // Determine access size from the instruction.
            uint8_t AccessSize = compressedMemAccessSize(CsInstruction.id);

            // Build synthetic IndirectOp from IMM + base REG.
            relations::IndirectOp MemOp = {
                registerName(RISCV_REG_INVALID),       // segment = NONE
                registerName(Details.operands[2].reg), // base register
                registerName(RISCV_REG_INVALID),       // index = NONE
                1,                                     // multiplier
                Details.operands[1].imm,               // displacement
                AccessSize                             // size
            };
            uint64_t MemOpIndex = Facts.Operands.add(MemOp);

            // Order as [MEM, REG] (after rotation: dest goes to end).
            OpCodes.push_back(MemOpIndex);
            OpCodes.push_back(RegOpIndex);
        }
        else
        {
            for(int i = 0; i < OpCount; i++)
            {
                // Load capstone operand.
                const cs_riscv_op& CsOp = Details.operands[i];

                // Build operand for datalog fact.
                std::optional<relations::Operand> Op = build(CsOp);
                if(!Op)
                {
                    return std::nullopt;
                }

                // Convert PC-relative branch/jump offsets to absolute addresses.
                if(IsBranchJump && CsOp.type == RISCV_OP_IMM)
                {
                    auto& ImmOp = std::get<relations::ImmOp>(*Op);
                    ImmOp.Value += static_cast<int64_t>(CsInstruction.address);
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
    }

    gtirb::Addr Addr(CsInstruction.address);
    uint64_t Size(CsInstruction.size);
    return relations::Instruction{Addr, Size, "", Name, OpCodes, 0, 0};
}

std::optional<relations::Operand> RiscVLoader::build(const cs_riscv_op& CsOp)
{
    using namespace relations;

    auto registerName = [this](unsigned int Reg) {
        return (Reg == RISCV_REG_INVALID) ? "NONE" : uppercase(cs_reg_name(*CsHandle, Reg));
    };

    switch(CsOp.type)
    {
        case RISCV_OP_REG:
            return RegOp{registerName(CsOp.reg)};
        case RISCV_OP_IMM:
        {
            relations::ImmOp I = {CsOp.imm, 8};
            return I;
        }
        case RISCV_OP_MEM:
        {
            relations::IndirectOp I = {registerName(RISCV_REG_INVALID),
                                       registerName(CsOp.mem.base),
                                       registerName(RISCV_REG_INVALID),
                                       1,
                                       CsOp.mem.disp,
                                       8};
            return I;
        }
        case RISCV_OP_INVALID:
        default:
            break;
    }
    return std::nullopt;
}

uint8_t RiscVLoader::operandCount(const cs_insn& CsInstruction)
{
    const cs_riscv& Details = CsInstruction.detail->riscv;
    return Details.op_count;
}

uint8_t RiscVLoader::operandAccess(const cs_insn& CsInstruction, uint64_t Index)
{
    // RISC-V does not provide operand access information.
    return CS_AC_INVALID;
}
