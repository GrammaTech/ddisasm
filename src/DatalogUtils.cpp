//===- GtirbToDatalog.cpp ---------------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2019 GrammaTech, Inc.
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

void writeFacts(souffle::SouffleProgram* prog, const std::string& directory)
{
    std::ios_base::openmode filemask = std::ios::out;
    for(souffle::Relation* relation : prog->getInputRelations())
    {
        std::ofstream file(directory + relation->getName() + ".facts", filemask);
        souffle::SymbolTable symbolTable = relation->getSymbolTable();
        for(souffle::tuple tuple : *relation)
        {
            for(size_t i = 0; i < tuple.size(); i++)
            {
                if(i > 0)
                    file << "\t";
                if(relation->getAttrType(i)[0] == 's')
                    file << symbolTable.resolve(tuple[i]);
                else
                    file << tuple[i];
            }
            file << std::endl;
        }
        file.close();
    }
}

void GtirbToDatalog::populateEdgeProperties(souffle::tuple& T, const gtirb::EdgeLabel& Label)
{
    assert(Label.has_value() && "Found edge without a label");
    if(std::get<gtirb::ConditionalEdge>(*Label) == gtirb::ConditionalEdge::OnTrue)
        T << "true";
    else
        T << "false";
    if(std::get<gtirb::DirectEdge>(*Label) == gtirb::DirectEdge::IsIndirect)
        T << "true";
    else
        T << "false";
    switch(std::get<gtirb::EdgeType>(*Label))
    {
        case gtirb::EdgeType::Branch:
            T << "jump";
            break;
        case gtirb::EdgeType::Call:
            T << "call";
            break;
        case gtirb::EdgeType::Fallthrough:
            T << "fallthrough";
            break;
        case gtirb::EdgeType::Return:
            T << "return";
            break;
        case gtirb::EdgeType::Syscall:
            T << "syscall";
            break;
        case gtirb::EdgeType::Sysret:
            T << "sysret";
            break;
    }
}

void GtirbToDatalog::populateBlocks(gtirb::Module& M)
{
    auto* BlocksRel = Prog->getRelation("block");
    for(auto& Block : M.blocks())
    {
        souffle::tuple T(BlocksRel);
        T << static_cast<uint64_t>(Block.getAddress());
        BlocksRel->insert(T);
    }
}

void GtirbToDatalog::populateCfgEdges(gtirb::Module& M)
{
    std::map<gtirb::ProxyBlock*, std::string> InvSymbolMap;
    for(auto& Symbol : M.symbols())
    {
        if(gtirb::ProxyBlock* Proxy = Symbol.getReferent<gtirb::ProxyBlock>())
            InvSymbolMap[Proxy] = Symbol.getName();
    }
    gtirb::CFG& Cfg = M.getCFG();
    auto* EdgeRel = Prog->getRelation("cfg_edge");
    auto* TopEdgeRel = Prog->getRelation("cfg_edge_to_top");
    auto* SymbolEdgeRel = Prog->getRelation("cfg_edge_to_symbol");
    for(auto& Edge : Cfg.m_edges)
    {
        if(gtirb::Block* Src = dyn_cast<gtirb::Block>(Cfg[Edge.m_source]))
        {
            if(gtirb::Block* Dest = dyn_cast<gtirb::Block>(Cfg[Edge.m_target]))
            {
                souffle::tuple T(EdgeRel);
                T << static_cast<uint64_t>(Src->getAddress())
                  << static_cast<uint64_t>(Dest->getAddress());
                populateEdgeProperties(T, Edge.get_property());
                EdgeRel->insert(T);
            }

            if(gtirb::ProxyBlock* Dest = dyn_cast<gtirb::ProxyBlock>(Cfg[Edge.m_target]))
            {
                auto foundSymbol = InvSymbolMap.find(Dest);
                if(foundSymbol != InvSymbolMap.end())
                {
                    souffle::tuple T(SymbolEdgeRel);
                    T << static_cast<uint64_t>(Src->getAddress()) << foundSymbol->second;
                    populateEdgeProperties(T, Edge.get_property());
                    SymbolEdgeRel->insert(T);
                }
                else
                {
                    souffle::tuple T(TopEdgeRel);
                    T << static_cast<uint64_t>(Src->getAddress());
                    populateEdgeProperties(T, Edge.get_property());
                    TopEdgeRel->insert(T);
                }
            }
        }
    }
}

void GtirbToDatalog::populateSccs(gtirb::Module& M)
{
    auto* InSccRel = Prog->getRelation("in_scc");
    auto* SccTable = M.getAuxData<std::map<gtirb::UUID, int>>("SCCs");
    assert(SccTable && "SCCs AuxData table missing from GTIRB module");
    std::vector<int> SccBlockIndex;
    for(auto& Block : M.blocks())
    {
        auto Found = SccTable->find(Block.getUUID());
        assert(Found != SccTable->end() && "Block missing from SCCs table");
        if(SccBlockIndex.size() <= Found->second)
            SccBlockIndex.resize(Found->second + 1);
        souffle::tuple T(InSccRel);
        T << Found->second << SccBlockIndex[Found->second]++
          << static_cast<uint64_t>(Block.getAddress());
        InSccRel->insert(T);
    }
}