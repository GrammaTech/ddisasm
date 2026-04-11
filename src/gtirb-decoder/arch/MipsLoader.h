//===- MipsLoader.h --------------------------------------------*- C++ -*-===//
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
#ifndef SRC_GTIRB_DECODER_ARCH_MIPSDECODER_H_
#define SRC_GTIRB_DECODER_ARCH_MIPSDECODER_H_

#include <capstone/capstone.h>

#include <optional>
#include <string>
#include <tuple>

#include "../Relations.h"
#include "../core/InstructionLoader.h"

class MipsLoader : public InstructionLoader
{
public:
    enum class Endian
    {
        LITTLE,
        BIG
    };

    MipsLoader(uint8_t OperandWidth, cs_mode CsWidthMode, Endian E = Endian::BIG)
        : InstructionLoader{4}, OperandSize{OperandWidth}
    {
        // Setup Capstone engine.
        unsigned int Mode0 = CsWidthMode;
        if(E == Endian::BIG)
            Mode0 |= CS_MODE_BIG_ENDIAN;
        else if(E == Endian::LITTLE)
            Mode0 |= CS_MODE_LITTLE_ENDIAN;

        cs_mode Mode = (cs_mode)Mode0;
        [[maybe_unused]] cs_err Err = cs_open(CS_ARCH_MIPS, Mode, CsHandle.get());
        assert(Err == CS_ERR_OK && "Failed to initialize MIPS disassembler.");
        cs_option(*CsHandle, CS_OPT_DETAIL, CS_OPT_ON);
    }

protected:
    void decode(BinaryFacts& Facts, const uint8_t* Bytes, uint64_t Size, uint64_t Addr) override;
    uint8_t operandCount(const cs_insn& CsInstruction) override;
    uint8_t operandAccess(const cs_insn& CsInstruction, uint64_t Index) override;

private:
    std::optional<relations::Operand> build(const cs_mips_op& CsOp);
    std::optional<relations::Instruction> build(BinaryFacts& Facts, const cs_insn& CsInstruction);
    std::tuple<std::string, std::string> splitMnemonic(const cs_insn& CsInstruction);

    uint8_t OperandSize;
};

// Convenience subclasses for backward compatibility.
class Mips32Loader : public MipsLoader
{
public:
    Mips32Loader(Endian E = Endian::BIG) : MipsLoader(4, CS_MODE_MIPS32, E)
    {
    }
};

class Mips64Loader : public MipsLoader
{
public:
    Mips64Loader(Endian E = Endian::BIG) : MipsLoader(4, CS_MODE_MIPS64, E)
    {
    }
};

#endif // SRC_GTIRB_DECODER_ARCH_MIPSDECODER_H_
