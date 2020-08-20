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

#include <map>
#include <string>

#include <capstone/capstone.h>

#include "../Relations.h"
#include "../core/InstructionLoader.h"

namespace relations
{
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

    using Arm64Operand = std::variant<ImmOp, RegOp, IndirectOp, PrefetchOp, BarrierOp>;

    struct Arm64OperandTable : public OperandTable
    {
        using OperandTable::operator();

        uint64_t operator()(BarrierOp& Op)
        {
            return add(BarrierTable, Op);
        }

        uint64_t operator()(PrefetchOp& Op)
        {
            return add(PrefetchTable, Op);
        }

        std::map<BarrierOp, uint64_t> BarrierTable;
        std::map<PrefetchOp, uint64_t> PrefetchTable;
    };
} // namespace relations

class Arm64Loader : public InstructionLoader
{
public:
    using Instruction = relations::Instruction;
    using Operand = relations::Arm64Operand;
    using OperandTable = relations::Arm64OperandTable;

    Arm64Loader() : InstructionLoader(4)
    {
        [[maybe_unused]] cs_err Err = cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &CsHandle);
        assert(Err == CS_ERR_OK && "Failed to initialize ARM64 disassembler.");
        cs_option(CsHandle, CS_OPT_DETAIL, CS_OPT_ON);
    }
    ~Arm64Loader()
    {
        cs_close(&CsHandle);
    }

    void operator()(const gtirb::Module& Module, DatalogProgram& Program) override;

    std::optional<Instruction> decode(const uint8_t* Bytes, uint64_t Size, uint64_t Addr) override;

private:
    OperandTable Operands;

    std::optional<Operand> build(const cs_arm64_op& CsOp);
    std::optional<Instruction> build(const cs_insn& CsInstruction);

    csh CsHandle = CS_ERR_ARCH;
};

std::optional<const char*> barrierValue(const arm64_barrier_op Op);
std::optional<const char*> prefetchValue(const arm64_prefetch_op Op);

namespace souffle
{
    souffle::tuple& operator<<(souffle::tuple& T, const relations::BarrierOp& Op);

    souffle::tuple& operator<<(souffle::tuple& T, const relations::PrefetchOp& Op);
} // namespace souffle

#endif // SRC_GTIRB_DECODER_ARCH_ARM64DECODER_H_
