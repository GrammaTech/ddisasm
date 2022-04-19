//===- Mips32Loader.h -------------------------------------------*- C++ -*-===//
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
#ifndef SRC_GTIRB_DECODER_ARCH_MIPS32DECODER_H_
#define SRC_GTIRB_DECODER_ARCH_MIPS32DECODER_H_

#include <capstone/capstone.h>

#include <optional>
#include <string>
#include <tuple>

#include "../Relations.h"
#include "../core/InstructionLoader.h"

class Mips32Loader : public InstructionLoader
{
public:
    enum class Endian
    {
        LITTLE,
        BIG
    };

    Mips32Loader(Endian E = Endian::BIG) : InstructionLoader{4}
    {
        // Setup Capstone engine.
        unsigned int Mode0 = CS_MODE_MIPS32;
        if(E == Endian::BIG)
            Mode0 |= CS_MODE_BIG_ENDIAN;
        else if(E == Endian::LITTLE)
            Mode0 |= CS_MODE_LITTLE_ENDIAN;

        cs_mode Mode = (cs_mode)Mode0;
        [[maybe_unused]] cs_err Err = cs_open(CS_ARCH_MIPS, Mode, CsHandle.get());
        assert(Err == CS_ERR_OK && "Failed to initialize MIPS32 disassembler.");
        cs_option(*CsHandle, CS_OPT_DETAIL, CS_OPT_ON);
    }

protected:
    void decode(BinaryFacts& Facts, const uint8_t* Bytes, uint64_t Size, uint64_t Addr) override;

private:
    std::optional<relations::Operand> build(const cs_mips_op& CsOp);
    std::optional<relations::Instruction> build(BinaryFacts& Facts, const cs_insn& CsInstruction);
    std::tuple<std::string, std::string> splitMnemonic(const cs_insn& CsInstruction);
};

#endif // SRC_GTIRB_DECODER_ARCH_MIPS32DECODER_H_
