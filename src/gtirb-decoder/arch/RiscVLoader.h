//===- RiscVLoader.h -------------------------------------------*- C++ -*-===//
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
#ifndef SRC_GTIRB_DECODER_ARCH_RISCVDECODER_H_
#define SRC_GTIRB_DECODER_ARCH_RISCVDECODER_H_

#include <capstone/capstone.h>

#include <optional>
#include <string>
#include <tuple>

#include "../Relations.h"
#include "../core/InstructionLoader.h"

class RiscVLoader : public InstructionLoader
{
public:
    RiscVLoader(cs_mode CsWidthMode, uint8_t DefaultCompressedMemSize, bool HasCJal)
        : InstructionLoader{2}, // RISC-V min instruction size is 2 (compressed) or 4 bytes
          DefaultCompressedMemSize{DefaultCompressedMemSize},
          HasCJal{HasCJal}
    {
        cs_mode Mode = (cs_mode)(CsWidthMode | CS_MODE_RISCVC | CS_MODE_LITTLE_ENDIAN);
        [[maybe_unused]] cs_err Err = cs_open(CS_ARCH_RISCV, Mode, CsHandle.get());
        assert(Err == CS_ERR_OK && "Failed to initialize RISC-V disassembler.");
        cs_option(*CsHandle, CS_OPT_DETAIL, CS_OPT_ON);
    }

protected:
    void decode(BinaryFacts& Facts, const uint8_t* Bytes, uint64_t Size, uint64_t Addr) override;
    uint8_t operandCount(const cs_insn& CsInstruction) override;
    uint8_t operandAccess(const cs_insn& CsInstruction, uint64_t Index) override;

private:
    std::optional<relations::Operand> build(const cs_riscv_op& CsOp);
    std::optional<relations::Instruction> build(BinaryFacts& Facts, const cs_insn& CsInstruction);
    std::tuple<std::string, std::string> splitMnemonic(const cs_insn& CsInstruction);

    bool isBranchJump(unsigned int InsnId) const;
    uint8_t compressedMemAccessSize(unsigned int InsnId) const;

    uint8_t DefaultCompressedMemSize;
    bool HasCJal;
};

// Convenience subclasses for backward compatibility.
class RiscV32Loader : public RiscVLoader
{
public:
    // RV32: C.JAL exists; compressed mem default access size is 4 (LW/SW)
    RiscV32Loader() : RiscVLoader(CS_MODE_RISCV32, 4, true)
    {
    }
};

class RiscV64Loader : public RiscVLoader
{
public:
    // RV64: no C.JAL; compressed mem default access size is 8 (LD/SD)
    RiscV64Loader() : RiscVLoader(CS_MODE_RISCV64, 8, false)
    {
    }
};

#endif // SRC_GTIRB_DECODER_ARCH_RISCVDECODER_H_
