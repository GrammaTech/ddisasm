//===- NoReturnPass.cpp -----------------------------------------*- C++ -*-===//
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

#include "NoReturnPass.h"
#include <souffle/CompiledSouffle.h>
#include "../DatalogUtils.h"

void NoReturnPass::populateSouffleProg(std::shared_ptr<souffle::SouffleProgram> P, gtirb::Module& M)
{
    GtirbToDatalog Loader(P);
    Loader.populateSccs(M);
    Loader.populateCfgEdges(M);
}

std::set<gtirb::CodeBlock*> NoReturnPass::updateCFG(std::shared_ptr<souffle::SouffleProgram> P,
                                                    gtirb::Module& M)
{
    std::set<gtirb::CodeBlock*> NoReturn;
    for(auto& Output : *P->getRelation("block_call_no_return"))
    {
        gtirb::Addr BlockAddr(Output[0]);
        // this should correspond to only one block
        for(auto& Block : M.findCodeBlocksOn(BlockAddr))
        {
            NoReturn.insert(&Block);
        }
    }
    gtirb::CFG& Cfg = M.getIR()->getCFG();
    boost::remove_edge_if(
        [&](auto Edge) {
            gtirb::EdgeLabel Label = *static_cast<const gtirb::EdgeLabel*>(Edge.get_property());
            if(auto* Block = dyn_cast<gtirb::CodeBlock>(Cfg[Edge.m_source]))
                return NoReturn.count(Block) && Label
                       && std::get<gtirb::EdgeType>(*Label) == gtirb::EdgeType::Fallthrough;
            return false;
        },
        Cfg);
    return NoReturn;
}

void NoReturnPass::setDebugDir(std::string Path)
{
    DebugDir = Path;
}

std::set<gtirb::CodeBlock*> NoReturnPass::computeNoReturn(gtirb::Module& M, unsigned int NThreads)
{
    auto Prog = std::shared_ptr<souffle::SouffleProgram>(
        souffle::ProgramFactory::newInstance("souffle_no_return"));
    if(!Prog)
    {
        std::cerr << "Could not create souffle_no_return program" << std::endl;
        exit(1);
    }
    populateSouffleProg(Prog, M);
    Prog->setNumThreads(NThreads);
    Prog->run();
    if(DebugDir)
    {
        writeFacts(&*Prog, *DebugDir);
        Prog->printAll(*DebugDir);
    }
    return updateCFG(Prog, M);
}
