//===- NoReturnPass.cpp ---------------------------------------------*- C++ -*-===//
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
#include <souffle/SouffleInterface.h>
#include "GtirbToDatalog.h"

void populateSouffleProg(std::shared_ptr<souffle::SouffleProgram> P, gtirb::Module& M)
{
    GtirbToDatalog Loader(P);
    Loader.populateCfgEdges(M);
    Loader.populateSccs(M);
}

void updateCFG(std::shared_ptr<souffle::SouffleProgram> P, gtirb::Module& M)
{
    std::set<gtirb::Block*> NoReturn;
    for(auto& Output : *P->getRelation("block_call_no_return"))
    {
        uint64_t A;
        A = Output[0];
        gtirb::Addr BlockAddr(A);
        for(auto& Block : M.findBlock(BlockAddr))
        {
            NoReturn.insert(&Block);
        }
    }
    gtirb::CFG& Cfg = M.getCFG();
    boost::remove_edge_if(
        [&](auto Edge) {
            gtirb::EdgeLabel Label = *static_cast<const gtirb::EdgeLabel*>(Edge.get_property());
            if(auto* Block = dyn_cast<gtirb::Block>(Cfg[Edge.m_source]))
                return NoReturn.count(Block) && Label
                       && std::get<gtirb::EdgeType>(*Label) == gtirb::EdgeType::Fallthrough;
            return false;
        },
        Cfg);
}

// souffle::SouffleProgram* get_instance(std::string name);

void computeNoReturn(gtirb::Module& M)
{
    auto Prog = std::shared_ptr<souffle::SouffleProgram>(
        souffle::ProgramFactory::newInstance("souffle_no_return"));
    // auto Prog = get_instance("souffle_no_return");
    if(!Prog)
    {
        std::cerr << "Could not create souffle program" << std::endl;
        exit(1);
    }
    populateSouffleProg(Prog, M);
    Prog->run();
    updateCFG(Prog, M);
}