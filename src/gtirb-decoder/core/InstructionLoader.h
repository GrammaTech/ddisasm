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

#include <vector>

#include <gtirb/gtirb.hpp>

#include "../DatalogProgram.h"
#include "../Relations.h"

struct InstructionFacts
{
    template <typename T>
    uint64_t add(std::map<T, uint64_t>& OpTable, T& Op)
    {
        auto [Iter, Inserted] = OpTable.try_emplace(std::forward<T>(Op), Index);
        if(Inserted)
        {
            Index++;
        }
        return Iter->second;
    }

    uint64_t operator()(relations::ImmOp& Op)
    {
        return add(Imm, Op);
    }

    uint64_t operator()(relations::RegOp& Op)
    {
        return add(Reg, Op);
    }

    uint64_t operator()(relations::IndirectOp& Op)
    {
        return add(Indirect, Op);
    }

    // We reserve 0 for empty operators.
    uint64_t Index = 1;

    // Instruction facts.
    std::vector<relations::Instruction> Instructions;
    std::vector<gtirb::Addr> InvalidInstructions;

    // Operand facts.
    std::map<relations::ImmOp, uint64_t> Imm;
    std::map<relations::RegOp, uint64_t> Reg;
    std::map<relations::IndirectOp, uint64_t> Indirect;
};

template <typename T>
class InstructionLoader
{
public:
    virtual ~InstructionLoader(){};

    virtual void operator()(const gtirb::Module& Module, DatalogProgram& Program)
    {
        static_cast<T&> (*this)(Module, Program);
    }

protected:
    explicit InstructionLoader(uint8_t N) : InstructionSize{N} {};

    virtual void load(const gtirb::Module& Module)
    {
        for(const auto& Section : Module.sections())
        {
            bool Executable = Section.isFlagSet(gtirb::SectionFlag::Executable);
            if(Executable)
            {
                for(const auto& ByteInterval : Section.byte_intervals())
                {
                    load(ByteInterval);
                }
            }
        }
    }

    virtual void load(const gtirb::ByteInterval& ByteInterval)
    {
        assert(ByteInterval.getAddress() && "ByteInterval is non-addressable.");

        uint64_t Addr = static_cast<uint64_t>(*ByteInterval.getAddress());
        uint64_t Size = ByteInterval.getInitializedSize();
        auto Data = ByteInterval.rawBytes<const uint8_t>();

        while(Size > 0)
        {
            decode(Data, Size, Addr);
            Addr += InstructionSize;
            Data += InstructionSize;
            Size -= InstructionSize;
        }
    }

    // Disassemble bytes and build Instruction and Operand facts.
    virtual void decode(const uint8_t* Bytes, uint64_t Size, uint64_t Addr) = 0;

    // We default to decoding instructions at every byte offset.
    uint8_t InstructionSize = 1;

private:
    InstructionLoader(){};
    friend T;
};

// // Decorator for loading instructions from known code blocks.
// template <typename T>
// class CodeBlockLoader : public T
// {
// public:
//     using Instruction = typename T::Instruction;

//     void load(const gtirb::Module& Module) override
//     {
//         for(auto& Block : Module.code_blocks())
//         {
//             load(Block);
//         }
//     }

//     void load(const gtirb::CodeBlock& Block)
//     {
//         assert(Block.getAddress() && "Found code block without address.");
//         gtirb::Addr Addr = *Block.getAddress();

//         const gtirb::ByteInterval* ByteInterval = Block.getByteInterval();
//         assert(ByteInterval->getAddress() && "Found byte interval without address.");

//         assert(Addr < (*ByteInterval->getAddress() + ByteInterval->getInitializedSize())
//                && "Found uninitialized code block.");
//         auto Data = ByteInterval->rawBytes<const uint8_t>() + Block.getOffset();
//         uint64_t Size = ByteInterval->getInitializedSize() - Block.getOffset();

//         // TODO: Add `InstructionLimit` parameter for decoding a number of
//         //       instructions from the beginning of the code block.
//         if(std::optional<typename T::Instruction> Instruction =
//                T::decode(Data, Size, static_cast<uint64_t>(Addr)))
//         {
//             Instructions.push_back(*Instruction);
//         }
//     }

// protected:
//     std::vector<Instruction> Instructions;
// };

std::string uppercase(std::string S);

#endif // SRC_GTIRB_DECODER_CORE_INSTRUCTIONLOADER_H_
