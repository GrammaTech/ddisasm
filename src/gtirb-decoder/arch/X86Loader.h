//===- X86Loader.h ----------------------------------------------*- C++ -*-===//
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
#ifndef SRC_GTIRB_DECODER_ARCH_X86DECODER_H_
#define SRC_GTIRB_DECODER_ARCH_X86DECODER_H_

#include <optional>
#include <string>
#include <tuple>

#include <capstone/capstone.h>

#include "../Relations.h"
#include "../core/InstructionLoader.h"

struct X86Facts
{
    InstructionFacts Instructions;
    OperandFacts Operands;
};

class X86Loader : public InstructionLoader<X86Facts>
{
public:
    X86Loader() : InstructionLoader{1}
    {
        // Create smart Captone handle.
        CsHandle.reset(new csh(0), [](csh* Handle) {
            cs_close(Handle);
            delete Handle;
        });

        // Setup Capstone engine.
        [[maybe_unused]] cs_err Err = cs_open(CS_ARCH_X86, CS_MODE_32, CsHandle.get());
        assert(Err == CS_ERR_OK && "Failed to initialize X86 disassembler.");
        cs_option(*CsHandle, CS_OPT_DETAIL, CS_OPT_ON);
    }

protected:
    void decode(X86Facts& Facts, const uint8_t* Bytes, uint64_t Size, uint64_t Addr) override;
    void insert(const X86Facts& Facts, DatalogProgram& Program) override;

private:
    std::optional<relations::Operand> build(const cs_x86_op& CsOp);
    std::optional<relations::Instruction> build(X86Facts& Facts, const cs_insn& CsInstruction);
    std::tuple<std::string, std::string> splitMnemonic(const cs_insn& CsInstruction);

    std::shared_ptr<csh> CsHandle;
};

#endif // SRC_GTIRB_DECODER_ARCH_X86DECODER_H_
