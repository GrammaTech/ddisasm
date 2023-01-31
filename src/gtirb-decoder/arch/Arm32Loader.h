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
        [[maybe_unused]] cs_err Err = cs_open(CS_ARCH_ARM, (cs_mode)(CS_MODE_ARM), CsHandle.get());
        assert(Err == CS_ERR_OK && "Failed to initialize ARM disassembler.");
        cs_option(*CsHandle, CS_OPT_DETAIL, CS_OPT_ON);
    }

protected:
    // override from CodeBlockLoader
    void load(const gtirb::Module& Module, BinaryFacts& Facts) override
    {
        initCsModes(Module);
        InstructionLoader::load(Module, Facts);
    }

    void load(const gtirb::Module& Module, const gtirb::ByteInterval& ByteInterval,
              BinaryFacts& Facts) override;
    void load(const gtirb::ByteInterval& ByteInterval, BinaryFacts& Facts, size_t ExecutionMode,
              const std::vector<size_t>& CsModes);
    void decode([[maybe_unused]] BinaryFacts& Facts, [[maybe_unused]] const uint8_t* Bytes,
                [[maybe_unused]] uint64_t Size, [[maybe_unused]] uint64_t Addr) override
    {
        // For ARM32, we override the default implementation of load(ByteInterval,...), and the
        // overridden implementation calls decode() with a different signature (in order to pass
        // CsModes).
        assert(!"Not implemented for ARM32");
    }
    void decode(BinaryFacts& Facts, const uint8_t* Bytes, uint64_t Size, uint64_t Addr,
                const std::vector<size_t>& CsModes);
    uint8_t operandCount(const cs_insn& CsInstruction) override;
    uint8_t operandAccess(const cs_insn& CsInstruction, uint64_t Index) override;

private:
    struct OpndFactsT
    {
        std::vector<relations::Operand> Operands;
        std::optional<relations::ShiftedWithRegOp> ShiftedWithRegOp;
        std::optional<relations::ShiftedOp> ShiftedOp;

        void clear()
        {
            Operands.clear();
            ShiftedWithRegOp.reset();
            ShiftedOp.reset();
        }
    };

    void initCsModes(const gtirb::Module& Module);
    std::optional<relations::Operand> build(const cs_insn& CsInsn, const cs_arm_op& CsOp);
    void build(BinaryFacts& Facts, const cs_insn& CsInstruction, const OpndFactsT& OpFacts);
    bool collectOpndFacts(OpndFactsT& OpndFacts, const cs_insn& CsInstruction);

    std::map<size_t, std::vector<size_t>> CsModes;
};

#endif // SRC_GTIRB_DECODER_ARCH_ARM32DECODER_H_
