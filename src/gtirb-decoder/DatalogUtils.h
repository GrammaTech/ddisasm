//===- DatalogUtils.h -------------------------------------------*- C++ -*-===//
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
#ifndef DATALOG_UTILS_H_
#define DATALOG_UTILS_H_

#include <souffle/CompiledSouffle.h>
#include <souffle/SouffleInterface.h>
#include <gtirb/gtirb.hpp>

#include "../gtirb-decoder/DatalogLoader.h"

class BlocksLoader : public GtirbDecoder
{
public:
    void load(const gtirb::Module& M) override;
    void populate(DatalogProgram& P) override;

    struct Block
    {
        gtirb::Addr Address;
        uint64_t Size;
    };

    struct NextBlock
    {
        gtirb::Addr Block1;
        gtirb::Addr Block2;
    };

private:
    std::vector<Block> Blocks;
    std::vector<NextBlock> NextBlocks;
};

class InstructionsLoader : public GtirbDecoder
{
public:
    InstructionsLoader(int N) : InstructionLimit{N} {};

    void load(const gtirb::Module& M) override;
    void populate(DatalogProgram& P) override;

private:
    int InstructionLimit;
};

class CfgEdgesLoader : public GtirbDecoder
{
public:
    struct Edge
    {
        gtirb::Addr Source;
        gtirb::Addr Destination;
        std::string Conditional;
        std::string Indirect;
        std::string Type;
    };

    struct TopEdge
    {
        gtirb::Addr Source;
        std::string Conditional;
        std::string Indirect;
        std::string Type;
    };

    struct SymbolEdge
    {
        gtirb::Addr Source;
        std::string Symbol;
        std::string Conditional;
        std::string Indirect;
        std::string Type;
    };

    void load(const gtirb::Module& M) override;
    void populate(DatalogProgram& P) override;

    std::tuple<std::string, std::string, std::string> properties(const gtirb::EdgeLabel& L);

private:
    std::vector<Edge> Edges;
    std::vector<TopEdge> TopEdges;
    std::vector<SymbolEdge> SymbolEdges;
};

class SymbolicExpressionsLoader : public GtirbDecoder
{
public:
    struct SymbolicExpression
    {
        gtirb::Addr Address;
        gtirb::Addr Symbol;
        int64_t Offset;
    };

    struct SymbolMinusSymbol
    {
        gtirb::Addr Address;
        gtirb::Addr Symbol1;
        gtirb::Addr Symbol2;
        int64_t Offset;
    };

    void load(const gtirb::Module& M) override;
    void populate(DatalogProgram& P) override;

private:
    std::vector<SymbolicExpression> SymbolicExpressions;
    std::vector<SymbolMinusSymbol> SymbolMinusSymbols;
};

class FdeEntriesLoader : public GtirbDecoder
{
public:
    FdeEntriesLoader(const gtirb::Context* C) : Context(C){};

    void load(const gtirb::Module& M) override;
    void populate(DatalogProgram& P) override;

private:
    const gtirb::Context* Context;
    std::vector<std::pair<gtirb::Addr, gtirb::Addr>> FdeAddresses;
};

class FunctionEntriesLoader : public GtirbDecoder
{
public:
    FunctionEntriesLoader(const gtirb::Context* C) : Context(C){};

    void load(const gtirb::Module& M) override;
    void populate(DatalogProgram& P) override;

private:
    const gtirb::Context* Context;
    std::vector<gtirb::Addr> Functions;
};

class PaddingLoader : public GtirbDecoder
{
public:
    PaddingLoader(const gtirb::Context* C) : Context(C){};

    void load(const gtirb::Module& M) override;
    void populate(DatalogProgram& P) override;

private:
    const gtirb::Context* Context;
    std::vector<std::pair<gtirb::Addr, uint64_t>> Paddings;
};

namespace souffle
{
    souffle::tuple& operator<<(souffle::tuple& T, const BlocksLoader::Block& B);
    souffle::tuple& operator<<(souffle::tuple& T, const BlocksLoader::NextBlock& N);
} // namespace souffle

#endif
