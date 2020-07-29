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

void BlocksLoader::load(const gtirb::Module& Module)
{
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
}

void BlocksLoader::populate(DatalogProgram& Program)
{
    Program.insert("block", Blocks);
    Program.insert("next_block", NextBlocks);
}

void InstructionsLoader::load(const gtirb::Module& M)
{
    // // Decode and transform instructions for all blocks on the module.
    // std::vector<DlInstruction> Insns;
    // DlOperandTable OpDict;
    // for(auto& Block : M.code_blocks())
    // {
    //     assert(Block.getAddress() && "Found code block without address.");

    //     cs_insn* Insn;
    //     const gtirb::ByteInterval* Bytes = Block.getByteInterval();
    //     uint64_t InitSize = Bytes->getInitializedSize();
    //     assert(Bytes->getSize() == InitSize && "Found partially initialized code
    //     block."); size_t Count =
    //         cs_disasm(CsHandle.getHandle(), Bytes->rawBytes<uint8_t>(), InitSize,
    //                   static_cast<uint64_t>(*Block.getAddress()), InstructionLimit,
    //                   &Insn);

    //     // Exception-safe cleanup of instructions
    //     std::unique_ptr<cs_insn, std::function<void(cs_insn*)>> freeInsn(
    //         Insn, [Count](cs_insn* i) {
    //         cs_free(i, Count); });
    //     for(size_t i = 0; i < Count; ++i)
    //     {
    //         Insns.push_back(GtirbToDatalog::transformInstruction(CsHandle, OpDict, Insn[i]));
    //     }
    // }
}

void InstructionsLoader::populate(DatalogProgram& Program)
{
    // Program.insert("instruction", Instructions);
    // Program.insert("op_regdirect", Operands.RegTable);
    // Program.insert("op_immediate", Operands.ImmTable);
    // Program.insert("op_indirect", Operands.IndirectTable);
    // Program.insert("op_barrier", Operands.BarrierTable);
    // Program.insert("op_prefetch", Operands.PrefetchTable);
}

std::tuple<std::string, std::string, std::string> CfgEdgesLoader::properties(
    const gtirb::EdgeLabel& Label)
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

void CfgEdgesLoader::load(const gtirb::Module& M)
{
    std::map<const gtirb::ProxyBlock*, std::string> InvSymbolMap;
    for(auto& Symbol : M.symbols())
    {
        if(const gtirb::ProxyBlock* Proxy = Symbol.getReferent<gtirb::ProxyBlock>())
        {
            InvSymbolMap[Proxy] = Symbol.getName();
        }
    }

    const gtirb::CFG& Cfg = M.getIR()->getCFG();
    for(auto& Edge : Cfg.m_edges)
    {
        if(const gtirb::CodeBlock* Src = dyn_cast<gtirb::CodeBlock>(Cfg[Edge.m_source]))
        {
            std::optional<gtirb::Addr> SrcAddr = Src->getAddress();
            assert(SrcAddr && "Found source block without address.");

            auto [Conditional, Indirect, Type] = properties(Edge.get_property());

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
}

void CfgEdgesLoader::populate(DatalogProgram& Program)
{
    Program.insert("cfg_edge", Edges);
    Program.insert("cfg_edge_to_top", TopEdges);
    Program.insert("cfg_edge_to_symbol", SymbolEdges);
}

// void GtirbToDatalog::populateSccs(gtirb::Module& M)
// {
//     auto* InSccRel = Prog->getRelation("in_scc");
//     auto* SccTable = M.getAuxData<gtirb::schema::Sccs>();
//     assert(SccTable && "SCCs AuxData table missing from GTIRB module");
//     std::vector<int> SccBlockIndex;
//     for(auto& Block : M.code_blocks())
//     {
//         assert(Block.getAddress() && "Found code block without address.");
//         auto Found = SccTable->find(Block.getUUID());
//         assert(Found != SccTable->end() && "Block missing from SCCs table");
//         uint64_t SccIndex = Found->second;
//         if(SccBlockIndex.size() <= SccIndex)
//             SccBlockIndex.resize(SccIndex + 1);
//         souffle::tuple T(InSccRel);
//         T << SccIndex << SccBlockIndex[SccIndex]++ << *Block.getAddress();
//         InSccRel->insert(T);
//     }
// }

// void GtirbToDatalog::populateSymbolicExpressions(const gtirb::Module& M)
// {
//     auto* SymExprRel = Prog->getRelation("symbolic_expression");
//     auto* SymMinusSymRel = Prog->getRelation("symbol_minus_symbol");
//     for(const auto& SymExprElem : M.symbolic_expressions())
//     {
//         const gtirb::ByteInterval* Bytes = SymExprElem.getByteInterval();
//         const gtirb::SymbolicExpression& SymExpr = SymExprElem.getSymbolicExpression();
//         if(std::optional<gtirb::Addr> Addr = Bytes->getAddress(); Addr)
//         {
//             if(auto* AddrConst = std::get_if<gtirb::SymAddrConst>(&SymExpr))
//             {
//                 if(AddrConst->Sym->getAddress())
//                 {
//                     souffle::tuple T(SymExprRel);
//                     T << *Addr << *(AddrConst->Sym->getAddress()) << AddrConst->Offset;
//                     SymExprRel->insert(T);
//                 }
//             }
//             if(auto* AddrAddr = std::get_if<gtirb::SymAddrAddr>(&SymExpr))
//             {
//                 if(AddrAddr->Sym1->getAddress() && AddrAddr->Sym2->getAddress())
//                 {
//                     souffle::tuple T(SymMinusSymRel);
//                     T << *Addr << *(AddrAddr->Sym1->getAddress()) <<
//                     *(AddrAddr->Sym2->getAddress())
//                       << AddrAddr->Offset;
//                     SymMinusSymRel->insert(T);
//                 }
//             }
//         }
//     }
// }

// void GtirbToDatalog::populateFdeEntries(const gtirb::Context& Ctx, gtirb::Module& M)
// {
//     std::set<gtirb::Addr> FdeStart;
//     std::set<gtirb::Addr> FdeEnd;
//     auto* CfiDirectives = M.getAuxData<gtirb::schema::CfiDirectives>();
//     if(!CfiDirectives)
//         return;
//     for(auto& Pair : *CfiDirectives)
//     {
//         auto* Block =
//             dyn_cast<const gtirb::CodeBlock>(gtirb::Node::getByUUID(Ctx,
//             Pair.first.ElementId));
//         assert(Block && "Found CFI directive that does not belong to a block");

//         std::optional<gtirb::Addr> BlockAddr = Block->getAddress();
//         assert(BlockAddr && "Found code block without address.");

//         for(auto& Directive : Pair.second)
//         {
//             if(std::get<0>(Directive) == ".cfi_startproc")
//                 FdeStart.insert(*BlockAddr + Pair.first.Displacement);
//             if(std::get<0>(Directive) == ".cfi_endproc")
//                 FdeEnd.insert(*BlockAddr + Pair.first.Displacement);
//         }
//     }
//     assert(FdeStart.size() == FdeEnd.size() && "Malformed CFI directives");
//     auto StartIt = FdeStart.begin();
//     auto EndIt = FdeEnd.begin();
//     auto* FdeAddresses = Prog->getRelation("fde_addresses");
//     for(; StartIt != FdeStart.end(); ++StartIt, ++EndIt)
//     {
//         souffle::tuple T(FdeAddresses);
//         T << *StartIt << *EndIt;
//         FdeAddresses->insert(T);
//     }
// }

// void GtirbToDatalog::populateFunctionEntries(const gtirb::Context& Ctx, gtirb::Module& M)
// {
//     auto* FunctionEntries = M.getAuxData<gtirb::schema::FunctionEntries>();
//     if(!FunctionEntries)
//         return;
//     auto* FunctionEntryRel = Prog->getRelation("function_entry");
//     for(auto& Pair : *FunctionEntries)
//     {
//         for(auto& UUID : Pair.second)
//         {
//             if(auto* Block = dyn_cast<gtirb::CodeBlock>(gtirb::Node::getByUUID(Ctx,
//             UUID)))
//             {
//                 assert(Block->getAddress() && "Found code block without address.");
//                 souffle::tuple T(FunctionEntryRel);
//                 T << *Block->getAddress();
//                 FunctionEntryRel->insert(T);
//             }
//         }
//     }
// }

// void GtirbToDatalog::populatePadding(const gtirb::Context& Ctx, gtirb::Module& M)
// {
//     auto* Padding = M.getAuxData<gtirb::schema::Padding>();
//     if(!Padding)
//         return;
//     auto* PaddingRel = Prog->getRelation("padding");
//     for(auto& [Offset, Size] : *Padding)
//     {
//         souffle::tuple T(PaddingRel);
//         auto* ByteInterval =
//             dyn_cast_or_null<gtirb::ByteInterval>(gtirb::Node::getByUUID(Ctx,
//             Offset.ElementId));
//         assert(ByteInterval && "Failed to find ByteInterval by UUID.");
//         if(ByteInterval->getAddress())
//         {
//             gtirb::Addr Addr = *ByteInterval->getAddress() + Offset.Displacement;
//             T << Addr << Size;
//             PaddingRel->insert(T);
//         }
//     }
// }

namespace souffle
{
    souffle::tuple& operator<<(souffle::tuple& T, const BlocksLoader::Block& Block)
    {
        T << Block.Address << Block.Size;
        return T;
    }

    souffle::tuple& operator<<(souffle::tuple& T, const BlocksLoader::NextBlock& NextBlock)
    {
        T << NextBlock.Block1 << NextBlock.Block2;
        return T;
    }

    souffle::tuple& operator<<(souffle::tuple& T, const CfgEdgesLoader::Edge& Edge)
    {
        T << Edge.Source << Edge.Destination << Edge.Conditional << Edge.Indirect << Edge.Type;
        return T;
    }

    souffle::tuple& operator<<(souffle::tuple& T, const CfgEdgesLoader::TopEdge& Edge)
    {
        T << Edge.Source << Edge.Conditional << Edge.Type;
        return T;
    }

    souffle::tuple& operator<<(souffle::tuple& T, const CfgEdgesLoader::SymbolEdge& Edge)
    {
        T << Edge.Source << Edge.Symbol;
        return T;
    }
} // namespace souffle
