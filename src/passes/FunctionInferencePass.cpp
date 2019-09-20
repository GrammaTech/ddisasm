//===- FunctionInferencePass.cpp ---------------------------------------------*- C++ -*-===//
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

#include "FunctionInferencePass.h"
#include <souffle/CompiledSouffle.h>
#include <boost/uuid/uuid_generators.hpp>
#include "../DatalogUtils.h"

void FunctionInferencePass::populateSouffleProg(std::shared_ptr<souffle::SouffleProgram> P,
                                                gtirb::Context& Ctx, gtirb::Module& M)
{
    GtirbToDatalog Loader(P);
    Loader.populateBlocks(M);
    Loader.populateInstructions(M);
    Loader.populateCfgEdges(M);
    Loader.populateSymbolicExpressions(M);
    Loader.populateFdeEntries(Ctx, M);
    Loader.populateFunctionEntries(Ctx, M);
}

void FunctionInferencePass::updateFunctions(std::shared_ptr<souffle::SouffleProgram> P,
                                            gtirb::Module& M)
{
    std::map<gtirb::UUID, std::set<gtirb::UUID>> FunctionEntries;
    std::map<gtirb::Addr, gtirb::UUID> FunctionEntry2function;
    boost::uuids::random_generator Generator;
    for(auto& Output : *P->getRelation("function_entry_final"))
    {
        gtirb::Addr FunctionEntry(Output[0]);
        auto BlockRange = M.findBlock(FunctionEntry);
        if(BlockRange.begin() != BlockRange.end())
        {
            const gtirb::UUID& EntryBlockUUID = BlockRange.begin()->getUUID();
            gtirb::UUID FunctionUUID = Generator();
            FunctionEntry2function[FunctionEntry] = FunctionUUID;
            FunctionEntries[FunctionUUID].insert(EntryBlockUUID);
        }
    }
    std::map<gtirb::UUID, std::set<gtirb::UUID>> FunctionBlocks;
    for(auto& Output : *P->getRelation("in_function_final"))
    {
        gtirb::Addr BlockAddr(Output[0]), FunctionEntryAddr(Output[1]);
        auto BlockRange = M.findBlock(BlockAddr);
        if(BlockRange.begin() != BlockRange.end())
        {
            gtirb::Block* Block = &*BlockRange.begin();
            gtirb::UUID FunctionEntryUUID = FunctionEntry2function[FunctionEntryAddr];
            FunctionBlocks[FunctionEntryUUID].insert(Block->getUUID());
        }
    }
    M.removeAuxData("functionEntries");
    M.removeAuxData("functionBlocks");
    M.addAuxData("functionEntries", std::move(FunctionEntries));
    M.addAuxData("functionBlocks", std::move(FunctionBlocks));
}

void FunctionInferencePass::setDebugDir(std::string Path)
{
    DebugDir = Path;
}

void FunctionInferencePass::computeFunctions(gtirb::Context& Ctx, gtirb::Module& M)
{
    auto Prog = std::shared_ptr<souffle::SouffleProgram>(
        souffle::ProgramFactory::newInstance("souffle_function_inference"));
    if(!Prog)
    {
        std::cerr << "Could not create souffle_function_inference program" << std::endl;
        exit(1);
    }
    populateSouffleProg(Prog, Ctx, M);
    Prog->run();
    if(DebugDir)
    {
        writeFacts(&*Prog, *DebugDir);
        Prog->printAll(*DebugDir);
    }
    updateFunctions(Prog, M);
}