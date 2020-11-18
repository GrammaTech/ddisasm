//===- InstructionLoader.h --------------------------------------*- C++ -*-===//
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
#ifndef SRC_GTIRB_DECODER_CORE_INSTRUCTIONLOADER_H_
#define SRC_GTIRB_DECODER_CORE_INSTRUCTIONLOADER_H_

#include <gtirb/gtirb.hpp>
#include <vector>

#include "../DatalogProgram.h"
#include "../Relations.h"

class OperandFacts
{
public:
    uint64_t add(const relations::Operand& Op)
    {
        return std::visit(*this, Op);
    }

    uint64_t operator()(const relations::ImmOp& Op)
    {
        return index(Imm, Op);
    }

    uint64_t operator()(const relations::RegOp& Op)
    {
        return index(Reg, Op);
    }

    uint64_t operator()(const relations::IndirectOp& Op)
    {
        return index(Indirect, Op);
    }

    const std::map<relations::ImmOp, uint64_t>& imm() const
    {
        return Imm;
    }

    const std::map<relations::RegOp, uint64_t>& reg() const
    {
        return Reg;
    }

    const std::map<relations::IndirectOp, uint64_t>& indirect() const
    {
        return Indirect;
    }

protected:
    template <typename T>
    uint64_t index(std::map<T, uint64_t>& OpTable, const T& Op)
    {
        auto [Iter, Inserted] = OpTable.try_emplace(Op, Index);
        if(Inserted)
        {
            Index++;
        }
        return Iter->second;
    }

private:
    // We reserve 0 for empty operators.
    uint64_t Index = 1;

    std::map<relations::ImmOp, uint64_t> Imm;
    std::map<relations::RegOp, uint64_t> Reg;
    std::map<relations::IndirectOp, uint64_t> Indirect;
};

class InstructionFacts
{
public:
    void add(const relations::Instruction& I)
    {
        Instructions.push_back(I);
    }

    void invalid(gtirb::Addr A)
    {
        InvalidInstructions.push_back(A);
    }

    const std::vector<relations::Instruction>& instructions() const
    {
        return Instructions;
    }

    const std::vector<gtirb::Addr>& invalid() const
    {
        return InvalidInstructions;
    }

private:
    std::vector<relations::Instruction> Instructions;
    std::vector<gtirb::Addr> InvalidInstructions;
};

template <typename T>
class InstructionLoader
{
public:
    using FactsType = T;

    virtual ~InstructionLoader(){};

    void operator()(const gtirb::Module& Module, DatalogProgram& Program)
    {
        T Facts;
        load(Module, Facts);
        insert(Facts, Program);
    }

protected:
    explicit InstructionLoader(uint8_t N) : InstructionSize{N} {};

    virtual void insert(const T& Facts, DatalogProgram& Program) = 0;

    virtual void load(const gtirb::Module& Module, T& Facts)
    {
        for(const auto& Section : Module.sections())
        {
            bool Executable = Section.isFlagSet(gtirb::SectionFlag::Executable);
            if(Executable)
            {
                for(const auto& ByteInterval : Section.byte_intervals())
                {
                    load(ByteInterval, Facts);
                }
            }
        }
    }

    virtual void load(const gtirb::ByteInterval& ByteInterval, T& Facts)
    {
        assert(ByteInterval.getAddress() && "ByteInterval is non-addressable.");

        uint64_t Addr = static_cast<uint64_t>(*ByteInterval.getAddress());
        uint64_t Size = ByteInterval.getInitializedSize();
        auto Data = ByteInterval.rawBytes<const uint8_t>();

        while(Size > 0)
        {
            decode(Facts, Data, Size, Addr);
            Addr += InstructionSize;
            Data += InstructionSize;
            Size -= InstructionSize;
        }
    }

    // Disassemble bytes and build Instruction and Operand facts.
    virtual void decode(T& Facts, const uint8_t* Bytes, uint64_t Size, uint64_t Addr) = 0;

    // We default to decoding instructions at every byte offset.
    uint8_t InstructionSize = 1;
};

// Decorator for loading instructions from known code blocks.
template <typename T>
class CodeBlockLoader : public T
{
protected:
    using FactsType = typename T::FactsType;

    void load(const gtirb::Module& Module, FactsType& Facts) override
    {
        for(auto& Block : Module.code_blocks())
        {
            load(Block, Facts);
        }
    }

    void load(const gtirb::CodeBlock& Block, FactsType& Facts)
    {
        assert(Block.getAddress() && "Found code block without address.");
        gtirb::Addr Addr = *Block.getAddress();

        const gtirb::ByteInterval* ByteInterval = Block.getByteInterval();
        assert(ByteInterval->getAddress() && "Found byte interval without address.");

        assert(Addr < (*ByteInterval->getAddress() + ByteInterval->getInitializedSize())
               && "Found uninitialized code block.");
        auto Data = ByteInterval->rawBytes<const uint8_t>() + Block.getOffset();
        uint64_t Size = ByteInterval->getInitializedSize() - Block.getOffset();

        // TODO: Add `InstructionLimit` parameter for decoding a number of
        //       instructions from the beginning of the code block.
        T::decode(Facts, Data, Size, static_cast<uint64_t>(Addr));
    }
};

std::string uppercase(std::string S);

#endif // SRC_GTIRB_DECODER_CORE_INSTRUCTIONLOADER_H_
