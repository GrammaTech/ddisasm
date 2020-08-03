//===- DatalogLoader.cpp ----------------------------------------*- C++ -*-===//
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
#ifndef SRC_DATALOG_LOADER_H_
#define SRC_DATALOG_LOADER_H_

#include <optional>
#include <string>
#include <vector>

#include <souffle/CompiledSouffle.h>
#include <souffle/SouffleInterface.h>
#include <gtirb/gtirb.hpp>

#include "DatalogProgram.h"
#include "Relations.h"

class DatalogLoader
{
public:
    DatalogLoader(std::string N) : Name{N}, Loaders{} {};
    ~DatalogLoader() = default;

    // Common type definition of functions/functors that populate datalog relations.
    using Loader = std::function<void(const gtirb::Module&, DatalogProgram&)>;

    // Add function to this composite loader.
    void add(Loader Fn)
    {
        Loaders.push_back(Fn);
    }

    // Add functor to this composite loader.
    template <typename T, typename... Args>
    void add(Args&&... A)
    {
        Loaders.push_back(T{A...});
    }

    // Build a DatalogProgram (i.e. SouffleProgram).
    std::optional<DatalogProgram> load(const gtirb::Module& Module);
    std::optional<DatalogProgram> operator()(const gtirb::Module& Module)
    {
        return load(Module);
    };

private:
    std::string Name;
    std::vector<Loader> Loaders;
};

// Load binary format information: architecture, file format, entry point, etc.
void FormatLoader(const gtirb::Module& Module, DatalogProgram& Program);

// Load section properties.
void SectionLoader(const gtirb::Module& Module, DatalogProgram& Program);

// Load symbol information.
void SymbolLoader(const gtirb::Module& Module, DatalogProgram& Program);

// Load data sections.
class DataLoader
{
public:
    template <typename T>
    using Data = relations::Data<T>;

    enum class Pointer
    {
        DWORD = 4,
        QWORD = 8
    };

    DataLoader(Pointer N) : PointerSize{N} {};
    virtual ~DataLoader(){};

    virtual void operator()(const gtirb::Module& Module, DatalogProgram& Program);

    virtual void load(const gtirb::Module& Module);
    virtual void load(const gtirb::ByteInterval& Bytes);

    // Test that a value N is a possible address.
    virtual bool address(gtirb::Addr N)
    {
        return ((N >= Min) && (N <= Max));
    };

protected:
    Pointer PointerSize;
    gtirb::Addr Min, Max;
    std::vector<Data<uint8_t>> Bytes;
    std::vector<Data<gtirb::Addr>> Addresses;
};

// Load executable sections.
class InstructionLoader
{
public:
    InstructionLoader(uint8_t N) : InstructionSize{N} {};
    virtual ~InstructionLoader(){};

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

std::string uppercase(std::string S);

const char* binaryISA(gtirb::ISA Arch);
const char* binaryFormat(const gtirb::FileFormat Format);

#endif /* SRC_DATALOG_LOADER_H_ */
