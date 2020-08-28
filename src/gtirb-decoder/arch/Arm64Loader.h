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
} // namespace relations

class Arm64OperandFacts : public OperandFacts
{
public:
    virtual const std::map<relations::BarrierOp, uint64_t>& barrier()
    {
        return Barrier;
    }

    virtual const std::map<relations::PrefetchOp, uint64_t>& prefetch()
    {
        return Prefetch;
    }

    using OperandFacts::operator();

    uint64_t operator()(relations::BarrierOp& Op)
    {
        return add(Barrier, Op);
    }

    uint64_t operator()(relations::PrefetchOp& Op)
    {
        return add(Prefetch, Op);
    }

    uint64_t add(relations::Arm64Operand& Op)
    {
        return std::visit(*this, Op);
    }

protected:
    using OperandFacts::add;

private:
    std::map<relations::BarrierOp, uint64_t> Barrier;
    std::map<relations::PrefetchOp, uint64_t> Prefetch;
};

class Arm64Loader : public InstructionLoader
{
public:
    Arm64Loader() : InstructionLoader(4)
    {
        // Setup Capstone engine.
        [[maybe_unused]] cs_err Err = cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &CsHandle);
        assert(Err == CS_ERR_OK && "Failed to initialize ARM64 disassembler.");
        cs_option(CsHandle, CS_OPT_DETAIL, CS_OPT_ON);

        // Call cs_close when the last Arm64Loader is destroyed.
        CloseHandle.reset(new csh(CsHandle), cs_close);
    }

    void operator()(const gtirb::Module& Module, DatalogProgram& Program) override;

protected:
    void decode(const uint8_t* Bytes, uint64_t Size, uint64_t Addr) override;

private:
    InstructionFacts Instructions;
    Arm64OperandFacts Operands;

    std::optional<relations::Arm64Operand> build(const cs_arm64_op& CsOp);
    std::optional<relations::Instruction> build(const cs_insn& CsInstruction);

    std::shared_ptr<csh> CloseHandle;
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
