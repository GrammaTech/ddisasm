//===- Arm64Loader.h --------------------------------------------*- C++ -*-===//
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
#ifndef SRC_GTIRB_DECODER_ARCH_ARM64DECODER_H_
#define SRC_GTIRB_DECODER_ARCH_ARM64DECODER_H_

#include <capstone/capstone.h>

#include <map>
#include <string>

#include "../Relations.h"
#include "../core/InstructionLoader.h"

struct Arm64Facts
{
    InstructionFacts Instructions;
    OperandFacts Operands;
};

class Arm64Loader : public InstructionLoader<Arm64Facts>
{
public:
    Arm64Loader() : InstructionLoader(4)
    {
        // Create smart Captone handle.
        CsHandle.reset(new csh(0), [](csh* Handle) {
            cs_close(Handle);
            delete Handle;
        });

        // Setup Capstone engine.
        [[maybe_unused]] cs_err Err = cs_open(CS_ARCH_ARM64, CS_MODE_ARM, CsHandle.get());
        assert(Err == CS_ERR_OK && "Failed to initialize ARM64 disassembler.");
        cs_option(*CsHandle, CS_OPT_DETAIL, CS_OPT_ON);
    }

protected:
    void decode(Arm64Facts& Facts, const uint8_t* Bytes, uint64_t Size, uint64_t Addr) override;
    void insert(const Arm64Facts& Facts, DatalogProgram& Program) override;

private:
    std::optional<relations::Operand> build(const cs_insn& CsInsn, uint8_t OpIndex,
                                            const cs_arm64_op& CsOp);
    bool build(Arm64Facts& Facts, const cs_insn& CsInstruction);
    std::optional<std::string> operandString(const cs_insn& CsInsn, uint8_t Index);

    std::shared_ptr<csh> CsHandle;
};

std::optional<const char*> barrierValue(const arm64_barrier_op Op);
std::optional<const char*> prefetchValue(const arm64_prefetch_op Op);

#endif // SRC_GTIRB_DECODER_ARCH_ARM64DECODER_H_
