//===- AuxDataLoader.cpp ----------------------------------------*- C++ -*-===//
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
#include "AuxDataLoader.h"

#include "../../AuxDataSchema.h"
#include "../Relations.h"

void PaddingLoader::operator()(const gtirb::Module& Module, souffle::SouffleProgram& Program)
{
    std::vector<relations::Padding> PaddingBlocks;

    auto* Table = Module.getAuxData<gtirb::schema::Padding>();
    assert(Table && "Padding AuxData table missing from GTIRB module.");

    for(auto& [Offset, Size] : *Table)
    {
        auto* ByteInterval = gtirb::dyn_cast_or_null<gtirb::ByteInterval>(
            gtirb::Node::getByUUID(*Context, Offset.ElementId));
        assert(ByteInterval && "Failed to find ByteInterval by UUID.");
        if(ByteInterval->getAddress())
        {
            gtirb::Addr Addr = *ByteInterval->getAddress() + Offset.Displacement;
            PaddingBlocks.push_back({Addr, Size});
        }
    }

    relations::insert(Program, "padding", std::move(PaddingBlocks));
}

void FdeEntriesLoader::operator()(const gtirb::Module& Module, souffle::SouffleProgram& Program)
{
    std::set<gtirb::Addr> FdeStart;
    std::set<gtirb::Addr> FdeEnd;

    auto* CfiDirectives = Module.getAuxData<gtirb::schema::CfiDirectives>();
    assert(CfiDirectives && "CfiDirectives AuxData table missing from GTIRB module.");

    for(auto& Pair : *CfiDirectives)
    {
        auto* Block = gtirb::dyn_cast_or_null<const gtirb::CodeBlock>(
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

    relations::insert(Program, "fde_addresses", std::move(FdeAddresses));
}

void FunctionEntriesLoader::operator()(const gtirb::Module& Module,
                                       souffle::SouffleProgram& Program)
{
    std::vector<gtirb::Addr> Functions;

    auto* FunctionEntries = Module.getAuxData<gtirb::schema::FunctionEntries>();
    assert(FunctionEntries && "FunctionEntries AuxData table missing from GTIRB module.");

    for(auto& Pair : *FunctionEntries)
    {
        for(auto& UUID : Pair.second)
        {
            auto* Block =
                gtirb::dyn_cast_or_null<gtirb::CodeBlock>(gtirb::Node::getByUUID(*Context, UUID));
            assert(Block && "Found function entry does not belong to a code block");
            assert(Block->getAddress() && "Found code block without address.");
            Functions.push_back(*Block->getAddress());
        }
    }

    relations::insert(Program, "function_entry", std::move(Functions));
}

void SccLoader(const gtirb::Module& Module, souffle::SouffleProgram& Program)
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

    relations::insert(Program, "in_scc", std::move(InScc));
}
