//===- Arm64Decoder.h -------------------------------------------*- C++ -*-===//
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
#ifndef SRC_ARM64_DECODER_H_
#define SRC_ARM64_DECODER_H_

#include "DatalogLoader.h"

#include <capstone/capstone.h>

class Arm64Decoder : public InstructionDecoder
{
public:
    using Instruction = InstructionDecoder::Instruction;

    struct BarrierOp
    {
        std::string Value;
        bool operator<(const BarrierOp& Op) const noexcept
        {
            return Value < Op.Value;
        }
    };

    struct PrefetchOp
    {
        std::string Value;
        bool operator<(const PrefetchOp& Op) const noexcept
        {
            return Value < Op.Value;
        }
    };

    using Operand = std::variant<InstructionDecoder::ImmOp, InstructionDecoder::RegOp,
                                 InstructionDecoder::IndirectOp, PrefetchOp, BarrierOp>;

    struct OperandTable : public InstructionDecoder::OperandTable
    {
        // TODO: Why do we have to redefine these?
        uint64_t operator()(ImmOp Op)
        {
            return add(ImmTable, Op);
        }

        uint64_t operator()(RegOp Op)
        {
            return add(RegTable, Op);
        }

        uint64_t operator()(IndirectOp Op)
        {
            return add(IndirectTable, Op);
        }

        uint64_t operator()(BarrierOp Op)
        {
            return add(BarrierTable, Op);
        }

        uint64_t operator()(PrefetchOp Op)
        {
            return add(PrefetchTable, Op);
        }

        std::map<BarrierOp, uint64_t> BarrierTable;
        std::map<PrefetchOp, uint64_t> PrefetchTable;
    };

    Arm64Decoder()
    {
        [[maybe_unused]] cs_err Err = cs_open(CS_ARCH_ARM64, CS_MODE_64, &CsHandle);
        assert(Err == CS_ERR_OK && "Failed to initialize ARM64 disassembler.");
        cs_option(CsHandle, CS_OPT_DETAIL, CS_OPT_ON);
    }
    ~Arm64Decoder()
    {
        cs_close(&CsHandle);
    }

    std::optional<Instruction> disasm(const uint8_t* Bytes, uint64_t Size, uint64_t Addr) override;

private:
    OperandTable Operands;

    std::optional<Operand> build(const cs_arm64_op& CsOp);
    std::optional<Instruction> build(const cs_insn& CsInstruction);
    std::tuple<std::string, std::string> splitMnemonic(const cs_insn& CsInstruction);

    csh CsHandle = CS_ERR_ARCH;
};

#endif /* SRC_ARM64_DECODER_H_ */
