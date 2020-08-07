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

// Load executable sections.
class InstructionLoader
{
public:
    explicit InstructionLoader(uint8_t N) : InstructionSize{N} {};

    using Instruction = relations::Instruction;
    using Operand = relations::Operand;
    using OperandTable = relations::OperandTable;

    virtual void operator()(const gtirb::Module& Module, DatalogProgram& Program);

    virtual void load(const gtirb::Module& Module);
    virtual void load(const gtirb::ByteInterval& Bytes);

    // Disassemble bytes and build Instruction and Operand facts.
    virtual std::optional<Instruction> decode(const uint8_t* Bytes, uint64_t Size,
                                              uint64_t Addr) = 0;

protected:
    uint8_t InstructionSize = 1;
    OperandTable Operands;
    std::vector<Instruction> Instructions;
    std::vector<gtirb::Addr> InvalidInstructions;
};

// Decorator for loading instructions from known code blocks.
template <typename T>
class CodeBlockLoader : public T
{
public:
    using Instruction = typename T::Instruction;

    void load(const gtirb::Module& Module) override
    {
        for(auto& Block : Module.code_blocks())
        {
            load(Block);
        }
    }

    void load(const gtirb::CodeBlock& Block)
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
        if(std::optional<typename T::Instruction> Instruction =
               T::decode(Data, Size, static_cast<uint64_t>(Addr)))
        {
            Instructions.push_back(*Instruction);
        }
    }

protected:
    std::vector<Instruction> Instructions;
};

std::string uppercase(std::string S);

#endif // SRC_GTIRB_DECODER_CORE_INSTRUCTIONLOADER_H_
