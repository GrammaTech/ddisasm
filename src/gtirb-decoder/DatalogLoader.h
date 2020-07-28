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

class GtirbDecoder
{
public:
    virtual void load(const gtirb::Module& M) = 0;
    virtual void populate(DatalogProgram& P) = 0;
};

class DataDecoder : public GtirbDecoder
{
public:
    template <class T>
    struct Data
    {
        gtirb::Addr Addr;
        T Item;
    };

    void load(const gtirb::Module& M) override;
    void load(const gtirb::ByteInterval& I);
    void populate(DatalogProgram& P) override;

private:
    std::vector<Data<uint8_t>> Bytes;
    std::vector<Data<gtirb::Addr>> Addresses;
};

class InstructionDecoder : public GtirbDecoder
{
public:
    struct Instruction
    {
        uint64_t Address;
        uint64_t Size;
        std::string Prefix;
        std::string Name;
        std::vector<uint64_t> OpCodes;
        uint8_t ImmediateOffset;
        uint8_t DisplacementOffset;
    };

    using ImmOp = int64_t;
    using RegOp = std::string;
    struct IndirectOp
    {
        std::string Reg1;
        std::string Reg2;
        std::string Reg3;
        int64_t Mult;
        int64_t Disp;
        int Size;

        constexpr bool operator<(const IndirectOp& Op) const noexcept
        {
            return std::tie(Reg1, Reg2, Reg3, Mult, Disp, Size)
                   < std::tie(Op.Reg1, Op.Reg2, Op.Reg3, Op.Mult, Op.Disp, Op.Size);
        };
    };

    using Operand = std::variant<ImmOp, RegOp, IndirectOp>;

    struct OperandTable
    {
        template <typename T>
        uint64_t add(std::map<T, uint64_t>& OpTable, T Op)
        {
            if(auto Pair = OpTable.find(Op); Pair != OpTable.end())
            {
                return Pair->second;
            }
            else
            {
                OpTable[Op] = Index;
                return Index++;
            }
        }

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

        // We reserve 0 for empty operators.
        uint64_t Index = 1;

        std::map<ImmOp, uint64_t> ImmTable;
        std::map<RegOp, uint64_t> RegTable;
        std::map<IndirectOp, uint64_t> IndirectTable;
    };

    void load(const gtirb::Module& M) override;
    void load(const gtirb::ByteInterval& I);
    void populate(DatalogProgram& P) override;

    virtual std::optional<Instruction> disasm(const uint8_t* Bytes, uint64_t Size,
                                              uint64_t Addr) = 0;

protected:
    OperandTable Operands;
    std::vector<Instruction> Instructions;
    std::vector<gtirb::Addr> InvalidInstructions;
};

class SectionDecoder : public GtirbDecoder
{
public:
    struct Section
    {
        std::string Name;
        uint64_t Size;
        gtirb::Addr Address;
        uint64_t Type;
        uint64_t Flags;
    };

    void load(const gtirb::Module& M) override;
    void populate(DatalogProgram& P) override;

private:
    std::vector<Section> Sections;
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

    void load(const gtirb::Module& M) override;
    void populate(DatalogProgram& P) override;

private:
    std::vector<Symbol> Symbols;
};

class FormatDecoder : public GtirbDecoder
{
public:
    void load(const gtirb::Module& M) override;
    void populate(DatalogProgram& P) override;

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

    DatalogLoader(std::string N) : Name{N}, Decoders{} {};
    ~DatalogLoader() = default;

    void decode(const gtirb::Module& M);
    std::optional<DatalogProgram> program();

    template <typename T>
    void add()
    {
        Decoders.push_back(std::make_shared<T>());
    }

private:
    std::string Name;
    GtirbDecoders Decoders;
};

namespace souffle
{
    souffle::tuple& operator<<(souffle::tuple& T, const gtirb::Addr& A);

    souffle::tuple& operator<<(souffle::tuple& T, const SymbolDecoder::Symbol& D);

    souffle::tuple& operator<<(souffle::tuple& T, const SectionDecoder::Section& S);

    template <typename Item>
    souffle::tuple& operator<<(souffle::tuple& T, const DataDecoder::Data<Item>& D);

    souffle::tuple& operator<<(souffle::tuple& T, const InstructionDecoder::Instruction& I);
} // namespace souffle

#endif /* SRC_DATALOG_LOADER_H_ */
