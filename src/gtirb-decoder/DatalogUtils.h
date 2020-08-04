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
#ifndef SRC_GTIRB_DECODER_DATALOGUTILS_H_
#define SRC_GTIRB_DECODER_DATALOGUTILS_H_

#include <string>
#include <tuple>
#include <utility>

#include <souffle/CompiledSouffle.h>
#include <souffle/SouffleInterface.h>
#include <gtirb/gtirb.hpp>

#include "Relations.h"

#include "DatalogProgram.h"

// Load CFG edges.
void CfgLoader(const gtirb::Module& M, DatalogProgram& P);

// Load strongly connected component facts.
void SccLoader(const gtirb::Module& M, DatalogProgram& P);

// Load code block edges.
void BlocksLoader(const gtirb::Module& M, DatalogProgram& P);

void SymbolicExpressionsLoader(const gtirb::Module& M, DatalogProgram& P);

struct PaddingLoader
{
    void operator()(const gtirb::Module& M, DatalogProgram& P);
    gtirb::Context* Context;
};

struct FdeEntriesLoader
{
    void operator()(const gtirb::Module& M, DatalogProgram& P);
    gtirb::Context* Context;
};

struct FunctionEntriesLoader
{
    void operator()(const gtirb::Module& M, DatalogProgram& P);
    gtirb::Context* Context;
};

std::tuple<std::string, std::string, std::string> edgeProperties(const gtirb::EdgeLabel& L);

namespace relations
{
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

    struct SccIndex
    {
        uint64_t Address;
        int64_t Index;
        gtirb::Addr Block;
    };

} // namespace relations

namespace souffle
{
    souffle::tuple& operator<<(souffle::tuple& T, const relations::Block& Block);

    souffle::tuple& operator<<(souffle::tuple& T, const relations::NextBlock& NextBlock);

    souffle::tuple& operator<<(souffle::tuple& T, const relations::Edge& Edge);

    souffle::tuple& operator<<(souffle::tuple& T, const relations::TopEdge& Edge);

    souffle::tuple& operator<<(souffle::tuple& T, const relations::SymbolEdge& Edge);

    souffle::tuple& operator<<(souffle::tuple& T, const relations::SymbolicExpression& Expr);

    souffle::tuple& operator<<(souffle::tuple& T, const relations::SymbolMinusSymbol& Expr);

    souffle::tuple& operator<<(souffle::tuple& T, const std::pair<gtirb::Addr, gtirb::Addr>& Pair);

    souffle::tuple& operator<<(souffle::tuple& T, const std::pair<gtirb::Addr, uint64_t>& Pair);

    souffle::tuple& operator<<(souffle::tuple& T, const relations::SccIndex& Scc);

} // namespace souffle

#endif // SRC_GTIRB_DECODER_DATALOGUTILS_H_
