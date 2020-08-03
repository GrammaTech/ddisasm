//===- DatalogUtils.cpp -----------------------------------------*- C++ -*-===//
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
#include "DatalogUtils.h"

#include "../AuxDataSchema.h"

void BlocksLoader(const gtirb::Module& Module, DatalogProgram& Program)
{
    std::vector<relations::Block> Blocks;
    std::vector<relations::NextBlock> NextBlocks;

    if(Module.code_blocks().empty())
    {
        return;
    }

    std::optional<gtirb::Addr> PrevBlockAddr = Module.code_blocks().begin()->getAddress();

    for(auto& Block : Module.code_blocks())
    {
        uint64_t BlockSize = Block.getSize();
        std::optional<gtirb::Addr> BlockAddr = Block.getAddress();
        assert(BlockAddr && PrevBlockAddr && "Found code block without address.");

        Blocks.push_back({*BlockAddr, BlockSize});
        if(*PrevBlockAddr < *BlockAddr)
        {
            NextBlocks.push_back({*PrevBlockAddr, *BlockAddr});
        }
        PrevBlockAddr = BlockAddr;
    }

    Program.insert("block", std::move(Blocks));
    Program.insert("next_block", std::move(NextBlocks));
}

std::tuple<std::string, std::string, std::string> edgeProperties(const gtirb::EdgeLabel& Label)
{
    assert(Label.has_value() && "Found edge without a label");

    std::string Conditional = "false";
    if(std::get<gtirb::ConditionalEdge>(*Label) == gtirb::ConditionalEdge::OnTrue)
    {
        Conditional = "true";
    }

    std::string Indirect = "false";
    if(std::get<gtirb::DirectEdge>(*Label) == gtirb::DirectEdge::IsIndirect)
    {
        Indirect = "true";
    }

    std::string Type;
    switch(std::get<gtirb::EdgeType>(*Label))
    {
        case gtirb::EdgeType::Branch:
            Type = "branch";
            break;
        case gtirb::EdgeType::Call:
            Type = "call";
            break;
        case gtirb::EdgeType::Fallthrough:
            Type = "fallthrough";
            break;
        case gtirb::EdgeType::Return:
            Type = "return";
            break;
        case gtirb::EdgeType::Syscall:
            Type = "syscall";
            break;
        case gtirb::EdgeType::Sysret:
            Type = "sysret";
            break;
    }

    return {Conditional, Indirect, Type};
}

void CfgLoader(const gtirb::Module& Module, DatalogProgram& Program)
{
    std::vector<relations::Edge> Edges;
    std::vector<relations::TopEdge> TopEdges;
    std::vector<relations::SymbolEdge> SymbolEdges;

    std::map<const gtirb::ProxyBlock*, std::string> InvSymbolMap;
    for(auto& Symbol : Module.symbols())
    {
        if(const gtirb::ProxyBlock* Proxy = Symbol.getReferent<gtirb::ProxyBlock>())
        {
            InvSymbolMap[Proxy] = Symbol.getName();
        }
    }

    const gtirb::CFG& Cfg = Module.getIR()->getCFG();
    for(auto& Edge : Cfg.m_edges)
    {
        if(const gtirb::CodeBlock* Src = dyn_cast<gtirb::CodeBlock>(Cfg[Edge.m_source]))
        {
            std::optional<gtirb::Addr> SrcAddr = Src->getAddress();
            assert(SrcAddr && "Found source block without address.");

            auto [Conditional, Indirect, Type] = edgeProperties(Edge.get_property());

            if(const gtirb::CodeBlock* Dest = dyn_cast<gtirb::CodeBlock>(Cfg[Edge.m_target]))
            {
                std::optional<gtirb::Addr> DestAddr = Dest->getAddress();
                assert(DestAddr && "Found destination block without address.");
                Edges.push_back({*SrcAddr, *DestAddr, Conditional, Indirect, Type});
            }

            if(const gtirb::ProxyBlock* Dest = dyn_cast<gtirb::ProxyBlock>(Cfg[Edge.m_target]))
            {
                auto It = InvSymbolMap.find(Dest);
                if(It != InvSymbolMap.end())
                {
                    std::string Symbol = It->second;
                    SymbolEdges.push_back({*SrcAddr, Symbol, Conditional, Indirect, Type});
                }
                else
                {
                    TopEdges.push_back({*SrcAddr, Conditional, Indirect, Type});
                }
            }
        }
    }

    Program.insert("cfg_edge", std::move(Edges));
    Program.insert("cfg_edge_to_top", std::move(TopEdges));
    Program.insert("cfg_edge_to_symbol", std::move(SymbolEdges));
}

void SymbolicExpressionsLoader(const gtirb::Module& Module, DatalogProgram& Program)
{
    std::vector<relations::SymbolicExpression> SymbolicExpressions;
    std::vector<relations::SymbolMinusSymbol> SymbolMinusSymbols;

    for(const auto& SymExprElem : Module.symbolic_expressions())
    {
        const gtirb::ByteInterval* Bytes = SymExprElem.getByteInterval();
        const gtirb::SymbolicExpression& SymExpr = SymExprElem.getSymbolicExpression();
        if(std::optional<gtirb::Addr> Addr = Bytes->getAddress(); Addr)
        {
            if(auto* AddrConst = std::get_if<gtirb::SymAddrConst>(&SymExpr))
            {
                std::optional<gtirb::Addr> Symbol = AddrConst->Sym->getAddress();
                if(Symbol)
                {
                    SymbolicExpressions.push_back({*Addr, *Symbol, AddrConst->Offset});
                }
            }
            if(auto* AddrAddr = std::get_if<gtirb::SymAddrAddr>(&SymExpr))
            {
                std::optional<gtirb::Addr> Symbol1 = AddrAddr->Sym1->getAddress();
                std::optional<gtirb::Addr> Symbol2 = AddrAddr->Sym2->getAddress();
                if(Symbol1 && Symbol2)
                {
                    SymbolMinusSymbols.push_back({*Addr, *Symbol1, *Symbol2, AddrAddr->Offset});
                }
            }
        }
    }

    Program.insert("symbolic_expression", SymbolicExpressions);
    Program.insert("symbol_minus_symbol", SymbolMinusSymbols);
}

void FdeEntriesLoader::operator()(const gtirb::Module& Module, DatalogProgram& Program)
{
    std::set<gtirb::Addr> FdeStart;
    std::set<gtirb::Addr> FdeEnd;

    auto* CfiDirectives = Module.getAuxData<gtirb::schema::CfiDirectives>();
    if(!CfiDirectives)
    {
        return;
    }

    for(auto& Pair : *CfiDirectives)
    {
        auto* Block = dyn_cast<const gtirb::CodeBlock>(
            gtirb::Node::getByUUID(*Context, Pair.first.ElementId));
        assert(Block && "Found CFI directive that does not belong to a block");

        std::optional<gtirb::Addr> BlockAddr = Block->getAddress();
        assert(BlockAddr && "Found code block without address.");

        for(auto& Directive : Pair.second)
        {
            if(std::get<0>(Directive) == ".cfi_startproc")
            {
                FdeStart.insert(*BlockAddr + Pair.first.Displacement);
            }
            if(std::get<0>(Directive) == ".cfi_endproc")
            {
                FdeEnd.insert(*BlockAddr + Pair.first.Displacement);
            }
        }
    }

    assert(FdeStart.size() == FdeEnd.size() && "Malformed CFI directives");

    std::vector<std::pair<gtirb::Addr, gtirb::Addr>> FdeAddresses;

    auto StartIt = FdeStart.begin();
    auto EndIt = FdeEnd.begin();
    for(; StartIt != FdeStart.end(); ++StartIt, ++EndIt)
    {
        FdeAddresses.push_back({*StartIt, *EndIt});
    }

    Program.insert("fde_addresses", std::move(FdeAddresses));
}

void FunctionEntriesLoader::operator()(const gtirb::Module& Module, DatalogProgram& Program)
{
    std::vector<gtirb::Addr> Functions;

    auto* FunctionEntries = Module.getAuxData<gtirb::schema::FunctionEntries>();
    if(!FunctionEntries)
    {
        return;
    }

    for(auto& Pair : *FunctionEntries)
    {
        for(auto& UUID : Pair.second)
        {
            if(auto* Block = dyn_cast<gtirb::CodeBlock>(gtirb::Node::getByUUID(*Context, UUID)))
            {
                assert(Block->getAddress() && "Found code block without address.");
                Functions.push_back(*Block->getAddress());
            }
        }
    }

    Program.insert("function_entry", std::move(Functions));
}

void PaddingLoader::operator()(const gtirb::Module& Module, DatalogProgram& Program)
{
    std::vector<std::pair<gtirb::Addr, uint64_t>> Padding;

    auto* Table = Module.getAuxData<gtirb::schema::Padding>();
    if(!Table)
    {
        return;
    }

    for(auto& [Offset, Size] : *Table)
    {
        auto* ByteInterval = dyn_cast_or_null<gtirb::ByteInterval>(
            gtirb::Node::getByUUID(*Context, Offset.ElementId));
        assert(ByteInterval && "Failed to find ByteInterval by UUID.");
        if(ByteInterval->getAddress())
        {
            gtirb::Addr Addr = *ByteInterval->getAddress() + Offset.Displacement;
            Padding.push_back({Addr, Size});
        }
    }

    Program.insert("padding", std::move(Padding));
}

void SccLoader(const gtirb::Module& Module, DatalogProgram& Program)
{
    auto* SccTable = Module.getAuxData<gtirb::schema::Sccs>();
    assert(SccTable && "SCCs AuxData table missing from GTIRB module");

    std::vector<relations::SccIndex> InScc;
    std::vector<int> SccBlockIndex;
    for(auto& Block : Module.code_blocks())
    {
        assert(Block.getAddress() && "Found code block without address.");

        auto Found = SccTable->find(Block.getUUID());
        assert(Found != SccTable->end() && "Block missing from SCCs table");

        uint64_t SccIndex = Found->second;
        if(SccBlockIndex.size() <= SccIndex)
        {
            SccBlockIndex.resize(SccIndex + 1);
        }

        InScc.push_back({SccIndex, SccBlockIndex[SccIndex]++, *Block.getAddress()});
    }

    Program.insert("in_scc", std::move(InScc));
}

namespace souffle
{
    souffle::tuple& operator<<(souffle::tuple& T, const relations::Block& Block)
    {
        T << Block.Address << Block.Size;
        return T;
    }

    souffle::tuple& operator<<(souffle::tuple& T, const relations::NextBlock& NextBlock)
    {
        T << NextBlock.Block1 << NextBlock.Block2;
        return T;
    }

    souffle::tuple& operator<<(souffle::tuple& T, const relations::Edge& Edge)
    {
        T << Edge.Source << Edge.Destination << Edge.Conditional << Edge.Indirect << Edge.Type;
        return T;
    }

    souffle::tuple& operator<<(souffle::tuple& T, const relations::TopEdge& Edge)
    {
        T << Edge.Source << Edge.Conditional << Edge.Indirect << Edge.Type;
        return T;
    }

    souffle::tuple& operator<<(souffle::tuple& T, const relations::SymbolEdge& Edge)
    {
        T << Edge.Source << Edge.Symbol << Edge.Conditional << Edge.Indirect << Edge.Type;
        return T;
    }

    souffle::tuple& operator<<(souffle::tuple& T, const relations::SymbolicExpression& Expr)
    {
        T << Expr.Address << Expr.Symbol << Expr.Offset;
        return T;
    }

    souffle::tuple& operator<<(souffle::tuple& T, const relations::SymbolMinusSymbol& Expr)
    {
        T << Expr.Address << Expr.Symbol1 << Expr.Symbol2 << Expr.Offset;
        return T;
    }

    souffle::tuple& operator<<(souffle::tuple& T, const std::pair<gtirb::Addr, gtirb::Addr>& Pair)
    {
        T << std::get<0>(Pair) << std::get<1>(Pair);
        return T;
    }

    souffle::tuple& operator<<(souffle::tuple& T, const std::pair<gtirb::Addr, uint64_t>& Pair)
    {
        T << std::get<0>(Pair) << std::get<1>(Pair);
        return T;
    }

    souffle::tuple& operator<<(souffle::tuple& T, const relations::SccIndex& Scc)
    {
        T << Scc.Address << Scc.Index << Scc.Block;
        return T;
    }

} // namespace souffle
