//===- Functors.cpp ---------------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2022 GrammaTech, Inc.
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
#include "Functors.h"

#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/strong_components.hpp>
#include <fstream>
#include <iostream>

#include "Endian.h"

FunctorContextManager FunctorContext;

const gtirb::ByteInterval* FunctorContextManager::getByteInterval(uint64_t EA, size_t Size)
{
    for(const auto& Section : Module->findSectionsOn(gtirb::Addr(EA)))
    {
        bool Executable = Section.isFlagSet(gtirb::SectionFlag::Executable);
        bool Initialized = Section.isFlagSet(gtirb::SectionFlag::Initialized);
        bool Loaded = Section.isFlagSet(gtirb::SectionFlag::Loaded);
        if(Loaded && (Executable || Initialized))
        {
            for(const auto& ByteInterval : Section.findByteIntervalsOn(gtirb::Addr(EA)))
            {
                uint64_t Addr = static_cast<uint64_t>(*ByteInterval.getAddress());
                uint64_t IntervalSize = ByteInterval.getInitializedSize();
                if(EA + Size > Addr + IntervalSize)
                {
                    continue;
                }
                return &ByteInterval;
            }
        }
    }
    return nullptr;
}

uint64_t functor_data_exists(uint64_t EA, size_t Size)
{
    const gtirb::ByteInterval* ByteInterval = FunctorContext.getByteInterval(EA, Size);
    return ByteInterval != nullptr ? 1 : 0;
}

void FunctorContextManager::readData(uint64_t EA, uint8_t* Buffer, size_t Count)
{
    const gtirb::ByteInterval* ByteInterval = FunctorContext.getByteInterval(EA, Count);
    if(ByteInterval == nullptr)
    {
        memset(Buffer, 0, Count);
        return;
    }
    uint64_t Addr = static_cast<uint64_t>(*ByteInterval->getAddress());
    auto Data = ByteInterval->rawBytes<const uint8_t>();

    // memcpy: safely handles unaligned requests.
    memcpy(Buffer, Data + EA - Addr, Count);
}

uint64_t functor_data_u8(uint64_t EA)
{
    uint8_t Value;
    FunctorContext.readData(EA, reinterpret_cast<uint8_t*>(&Value), sizeof(Value));
    return Value;
}

int64_t functor_data_s16(uint64_t EA)
{
    uint16_t Value;
    FunctorContext.readData(EA, reinterpret_cast<uint8_t*>(&Value), sizeof(Value));
    return static_cast<int16_t>(FunctorContext.IsBigEndian ? be16toh(Value) : le16toh(Value));
}

int64_t functor_data_s32(uint64_t EA)
{
    uint32_t Value;
    FunctorContext.readData(EA, reinterpret_cast<uint8_t*>(&Value), sizeof(Value));
    return static_cast<int32_t>(FunctorContext.IsBigEndian ? be32toh(Value) : le32toh(Value));
}

int64_t functor_data_s64(uint64_t EA)
{
    uint64_t Value;
    FunctorContext.readData(EA, reinterpret_cast<uint8_t*>(&Value), sizeof(Value));
    return static_cast<int64_t>(FunctorContext.IsBigEndian ? be64toh(Value) : le64toh(Value));
}

souffle::RamDomain build_scc_list([[maybe_unused]] souffle::SymbolTable* SymbolTable,
                                  souffle::RecordTable* RecordTable, souffle::RamDomain Edges)
{
    using OutEdgeListS = boost::vecS;
    using VertexListS = boost::vecS;
    using DirectedS = boost::directedS;
    using EdgeListS = boost::listS;
    using vertex_descriptor = boost::adjacency_list_traits<OutEdgeListS, VertexListS, DirectedS,
                                                           EdgeListS>::vertex_descriptor;

    // Build graph using Boost data structures
    using Graph = boost::adjacency_list<OutEdgeListS, VertexListS, DirectedS,
                                        // Vertices are addresses (uint64_t)
                                        uint64_t,
                                        // No edge properties
                                        boost::no_property,
                                        // track mapping between vertex descriptors and addresses
                                        std::unordered_map<uint64_t, vertex_descriptor>>;

    Graph Cfg = Graph();
    auto& AddressMap = Cfg[boost::graph_bundle];

    souffle::RamDomain Next = Edges;
    while(Next != 0)
    {
        const souffle::RamDomain* Node = RecordTable->unpack(Next, 2);
        const souffle::RamDomain* Edge = RecordTable->unpack(Node[0], 2);

        // Get vertices, adding to the graph if they aren't present yet.
        vertex_descriptor EdgeVerts[2];
        for(uint8_t I = 0; I < 2; I++)
        {
            if(auto It = AddressMap.find(Edge[I]); It != AddressMap.end())
            {
                EdgeVerts[I] = It->second;
            }
            else
            {
                // Insert new vertex.
                auto Vertex = add_vertex(Cfg);
                Cfg[Vertex] = Edge[I];
                AddressMap[Edge[I]] = Vertex;
                EdgeVerts[I] = Vertex;
            }
        }

        add_edge(EdgeVerts[0], EdgeVerts[1], Cfg);
        Next = Node[1];
    }

    // Find SCCs using Boost
    typedef std::map<vertex_descriptor, uint64_t> PropertyMap;
    PropertyMap SccComponents;
    boost::associative_property_map<PropertyMap> SccComponentsMap(SccComponents);
    strong_components(Cfg, SccComponentsMap);

    // Convert result back to Souffle types
    souffle::RamDomain HeadRecordID = 0;

    // Build SCC member lists
    for(auto Vertex : boost::make_iterator_range(vertices(Cfg)))
    {
        uint64_t Address = Cfg[Vertex];
        uint64_t SCC = SccComponents[Vertex];

        const souffle::RamDomain Membership[2] = {static_cast<souffle::RamDomain>(SCC),
                                                  static_cast<souffle::RamDomain>(Address)};
        souffle::RamDomain MembershipRecordID = RecordTable->pack(Membership, 2);
        const souffle::RamDomain ListNode[2] = {MembershipRecordID, HeadRecordID};
        HeadRecordID = RecordTable->pack(ListNode, 2);
    }

    return HeadRecordID;
}

void FunctorContextManager::useModule(const gtirb::Module* M)
{
    Module = M;

    // Check module's byte order
    switch(Module->getByteOrder())
    {
        case gtirb::ByteOrder::Big:
            IsBigEndian = true;
            break;
        case gtirb::ByteOrder::Little:
            IsBigEndian = false;
            break;
        case gtirb::ByteOrder::Undefined:
        default:
            std::cerr << "WARNING: GTIRB has undefined endianness (assuming little)\n";
            IsBigEndian = false;
    }
}

#ifndef __EMBEDDED_SOUFFLE__
/*
Load the GTIRB file from the debug directory

Used only for the interpreter.
*/
void FunctorContextManager::loadGtirb(void)
{
    const char* DebugDir = std::getenv("DDISASM_DEBUG_DIR");
    if(!DebugDir)
    {
        std::cerr << "ERROR: DDISASM_DEBUG_DIR not set\n";
        return;
    }
    std::string GtirbPath(DebugDir);
    GtirbPath.append("/binary.gtirb");

    GtirbContext = std::make_unique<gtirb::Context>();

    std::ifstream Stream(GtirbPath, std::ios::in | std::ios::binary);
    gtirb::ErrorOr<gtirb::IR*> Result = gtirb::IR::load(*GtirbContext, Stream);
    if(!Result)
    {
        std::cerr << "ERROR: Failed to load GTIRB: " << GtirbPath << "\n";
        return;
    }

    gtirb::IR* IR = *Result;

    // Locate the correct module
    const char* ModuleName = std::getenv("DDISASM_GTIRB_MODULE_NAME");
    if(!ModuleName)
    {
        std::cerr << "ERROR: DDISASM_GTIRB_MODULE_NAME not set\n";
        return;
    }

    auto Modules = IR->findModules(ModuleName);
    if(Modules.empty())
    {
        std::cerr << "ERROR: No module with name: " << ModuleName << "\n";
        return;
    }

    FunctorContext.useModule(&(*Modules.begin()));
}
#endif /* __EMBEDDED_SOUFFLE__ */
