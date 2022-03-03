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

struct InstructionWriteback
{
    gtirb::Addr Addr;
};

class Arm32InstructionFacts : public InstructionFacts
{
public:
    void writeback(const InstructionWriteback& writeback)
    {
        InstructionWritebackList.push_back(writeback);
    }

    const std::vector<InstructionWriteback>& writeback() const
    {
        return InstructionWritebackList;
    }

private:
    std::vector<InstructionWriteback> InstructionWritebackList;
};

struct Arm32Facts
{
    Arm32InstructionFacts Instructions;
    OperandFacts Operands;
};

class Arm32Loader : public InstructionLoader<Arm32Facts>
{
public:
    Arm32Loader() : InstructionLoader(4)
    {
        // Create smart Captone handle.
        CsHandle.reset(new csh(0), [](csh* Handle) {
            cs_close(Handle);
            delete Handle;
        });

        // Setup Capstone engine.
        [[maybe_unused]] cs_err Err =
            cs_open(CS_ARCH_ARM, (cs_mode)(CS_MODE_ARM | CS_MODE_V8), CsHandle.get());
        assert(Err == CS_ERR_OK && "Failed to initialize ARM disassembler.");
        cs_option(*CsHandle, CS_OPT_DETAIL, CS_OPT_ON);
    }

protected:
    void decode(Arm32Facts& Facts, const uint8_t* Bytes, uint64_t Size, uint64_t Addr) override;

    using InstructionLoader::load;
    void load(const gtirb::Module& Module, const gtirb::ByteInterval& ByteInterval,
              Arm32Facts& Facts) override;
    void load(const gtirb::ByteInterval& ByteInterval, Arm32Facts& Facts, bool Thumb);

    void insert(const Arm32Facts& Facts, DatalogProgram& Program) override;

private:
    std::optional<relations::Operand> build(const cs_arm_op& CsOp);
    bool build(Arm32Facts& Facts, const cs_insn& CsInstruction);

    std::shared_ptr<csh> CsHandle;
};

namespace souffle
{
    souffle::tuple& operator<<(souffle::tuple& T, const InstructionWriteback& writeback);
} // namespace souffle

#endif // SRC_GTIRB_DECODER_ARCH_ARM32DECODER_H_
