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
#ifndef SRC_GTIRB_DECODER_ARCH_ARM32DECODER_H_
#define SRC_GTIRB_DECODER_ARCH_ARM32DECODER_H_

#include <capstone/capstone.h>

#include <map>
#include <string>

#include "../Relations.h"
#include "../core/InstructionLoader.h"

class Arm32Loader : public InstructionLoader
{
public:
    Arm32Loader() : InstructionLoader(4)
    {
        // Setup Capstone engine.
        [[maybe_unused]] cs_err Err =
            cs_open(CS_ARCH_ARM, (cs_mode)(CS_MODE_ARM | CS_MODE_V8), CsHandle.get());
        assert(Err == CS_ERR_OK && "Failed to initialize ARM disassembler.");
        cs_option(*CsHandle, CS_OPT_DETAIL, CS_OPT_ON);

        Mclass = false;
        ArchtypeFromElf = false;
    }

protected:
    void decode([[maybe_unused]] BinaryFacts& Facts, [[maybe_unused]] const uint8_t* Bytes,
                [[maybe_unused]] uint64_t Size, [[maybe_unused]] uint64_t Addr) override
    {
        assert("Should not be called");
    }
    void decode(BinaryFacts& Facts, const uint8_t* Bytes, uint64_t Size, uint64_t Addr, bool Thumb);

    using InstructionLoader::load;
    void load(const gtirb::Module& Module, const gtirb::ByteInterval& ByteInterval,
              BinaryFacts& Facts) override;
    void load(const gtirb::ByteInterval& ByteInterval, BinaryFacts& Facts, bool Thumb);

private:
    std::optional<relations::Operand> build(const cs_insn& CsInsn, const cs_arm_op& CsOp);
    bool build(BinaryFacts& Facts, const cs_insn& CsInstruction, bool Update);

    bool Mclass;
    bool ArchtypeFromElf;
};

#endif // SRC_GTIRB_DECODER_ARCH_ARM32DECODER_H_
