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

#include <souffle/SouffleInterface.h>
#include <gtirb/gtirb.hpp>

#include "DatalogProgram.h"
#include "DatalogUtils.h"

class GtirbDecoder
{
public:
    virtual void load(const gtirb::Module& M) = 0;
    virtual void populate(DatalogProgram& P) = 0;
};

class DataDecoder
{
public:
    template <class T>
    struct Data
    {
        gtirb::Addr Addr;
        T Item;
    };

    virtual void load(const gtirb::ByteInterval& I);
    virtual void populate(DatalogProgram& P);

private:
    std::vector<Data<uint8_t>> Bytes;
    std::vector<Data<gtirb::Addr>> Addresses;
};

class InstructionDecoder
{
public:
    struct Instruction
    {
        uint64_t Address;
        long Size;
        std::string Prefix;
        std::string Name;
        std::vector<uint64_t> OpCodes;
        uint8_t ImmediateOffset;
        uint8_t DisplacementOffset;
    };

    virtual void load(const gtirb::ByteInterval& I);
    virtual void populate(DatalogProgram& P);

    // TODO: Make this a pure-virtual method, which will have to be implemented
    //       by an architecture-specific subclass
    virtual std::optional<Instruction> decode(const uint8_t* Bytes, uint64_t Size)
    {
        return std::nullopt;
    }

private:
    std::vector<Instruction> Instructions;
    std::vector<gtirb::Addr> InvalidInstructions;
};

class SectionDecoder : public GtirbDecoder
{
public:
    SectionDecoder() = default;
    SectionDecoder(InstructionDecoder& C, DataDecoder& D) : Code{C}, Data{D} {};

    virtual void load(const gtirb::Module& M) override;
    virtual void populate(DatalogProgram& P) override;

private:
    DataDecoder Data;
    InstructionDecoder Code;
};

class SymbolDecoder : public GtirbDecoder
{
public:
    struct Symbol
    {
        gtirb::Addr Addr;
        uint64_t Size;
        std::string Type;
        std::string Binding;
        std::string Visibility;
        uint64_t SectionIndex;
        std::string Name;
    };

    virtual void load(const gtirb::Module& M) override;
    virtual void populate(DatalogProgram& P) override;

private:
    std::vector<Symbol> Symbols;
};

class FormatDecoder : public GtirbDecoder
{
public:
    virtual void load(const gtirb::Module& M) override;
    virtual void populate(DatalogProgram& P) override;

private:
    std::string BinaryIsa;
    std::string BinaryFormat;
    std::string BinaryType;
    gtirb::Addr EntryPoint;
};

class DatalogLoader
{
public:
    using GtirbDecoders = std::vector<std::shared_ptr<GtirbDecoder>>;

    DatalogLoader(std::string N, GtirbDecoders D) : Name{N}, Decoders{D} {};
    ~DatalogLoader() = default;

    virtual void load(const gtirb::Module& M);
    virtual std::optional<DatalogProgram> program();

protected:
    std::string Name;
    GtirbDecoders Decoders;
};

#endif /* SRC_DATALOG_LOADER_H_ */
