//===- NoReturnPass.cpp -----------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2019-2023 GrammaTech, Inc.
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
#include "NoReturnPass.h"

#include "../gtirb-decoder/CompositeLoader.h"
#include "../gtirb-decoder/Relations.h"
#include "../gtirb-decoder/core/AuxDataLoader.h"
#include "../gtirb-decoder/core/EdgesLoader.h"

void NoReturnPass::transformImpl(AnalysisPassResult& Result, gtirb::Context& Context,
                                 gtirb::Module& Module)
{
    DatalogAnalysisPass::transformImpl(Result, Context, Module);

    std::set<gtirb::CodeBlock*> NoReturn;
    for(auto& Output : *Program->getRelation("block_call_no_return"))
    {
        gtirb::Addr BlockAddr(Output[0]);
        // this should correspond to only one block
        for(auto& Block : Module.findCodeBlocksOn(BlockAddr))
        {
            NoReturn.insert(&Block);
        }
    }
    gtirb::CFG& Cfg = Module.getIR()->getCFG();
    boost::remove_edge_if(
        [&](auto Edge) {
            gtirb::EdgeLabel Label = *static_cast<const gtirb::EdgeLabel*>(Edge.get_property());
            if(auto* Block = gtirb::dyn_cast<gtirb::CodeBlock>(Cfg[Edge.m_source]))
                return NoReturn.count(Block) && Label
                       && std::get<gtirb::EdgeType>(*Label) == gtirb::EdgeType::Fallthrough;
            return false;
        },
        Cfg);
}

void NoReturnPass::loadImpl(AnalysisPassResult& Result, const gtirb::Context& Context,
                            const gtirb::Module& Module, AnalysisPass* PreviousPass)
{
    // Build GTIRB loader.
    CompositeLoader Loader("souffle_no_return");
    Loader.add(SccLoader);
    Loader.add(CfgLoader);

    Program = Loader.load(Module);
    if(!Program)
    {
        Result.Errors.push_back("Could not create souffle_no_return program");
    }
}
