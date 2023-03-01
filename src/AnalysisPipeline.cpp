//===- AnalysisPipeline.cpp =-------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2023 GrammaTech, Inc.
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
#include "AnalysisPipeline.h"

#include "passes/DatalogAnalysisPass.h"

void AnalysisPipeline::configureDebugDir(const std::string &DebugDirRoot, bool MultiModule)
{
    for(auto &Pass : Passes)
    {
        Pass->configureDebugDir(DebugDirRoot, MultiModule);
    }
}

void AnalysisPipeline::setDatalogThreadCount(unsigned int Count)
{
    for(auto &Pass : Passes)
    {
        if(DatalogAnalysisPass *DatalogPass = dynamic_cast<DatalogAnalysisPass *>(Pass.get()))
        {
            DatalogPass->setThreadCount(Count);
        }
    }
}

void AnalysisPipeline::setDatalogProfileDir(const std::string &ProfileDir)
{
    for(auto &Pass : Passes)
    {
        if(DatalogAnalysisPass *DatalogPass = dynamic_cast<DatalogAnalysisPass *>(Pass.get()))
        {
            DatalogPass->setProfileDir(ProfileDir);
        }
    }
}

void AnalysisPipeline::enableSouffleOutputs()
{
    for(auto &Pass : Passes)
    {
        if(DatalogAnalysisPass *DatalogPass = dynamic_cast<DatalogAnalysisPass *>(Pass.get()))
        {
            DatalogPass->enableSouffleOutputs();
        }
    }
}

void AnalysisPipeline::configureSouffleInterpreter(const std::string &InterpreterDir,
                                                   const std::string &LibraryDir)
{
    for(auto &Pass : Passes)
    {
        if(DatalogAnalysisPass *DatalogPass = dynamic_cast<DatalogAnalysisPass *>(Pass.get()))
        {
            DatalogPass->configureSouffleInterpreter(InterpreterDir, LibraryDir);
        }
    }
}

std::set<std::string> AnalysisPipeline::getPassSlugs()
{
    std::set<std::string> Slugs;
    for(auto &Pass : Passes)
    {
        // only the datalog passes support hints
        if(dynamic_cast<DatalogAnalysisPass *>(Pass.get()))
        {
            Slugs.insert(Pass->getNameSlug());
        }
    }
    return Slugs;
}

void AnalysisPipeline::loadHints(const std::string &Path)
{
    DatalogHints.read(Path, getPassSlugs());
}

void AnalysisPipeline::notifyPassBegin(const AnalysisPass &Name)
{
    for(auto &Listener : Listeners)
    {
        Listener->notifyPassBegin(Name);
    }
}

void AnalysisPipeline::notifyPassEnd(const AnalysisPass &Pass)
{
    for(auto &Listener : Listeners)
    {
        Listener->notifyPassEnd(Pass);
    }
}
void AnalysisPipeline::notifyPassPhase(AnalysisPassPhase Phase, bool HasPhase)
{
    for(auto &Listener : Listeners)
    {
        Listener->notifyPassPhase(Phase, HasPhase);
    }
}
void AnalysisPipeline::notifyPassResult(AnalysisPassPhase Phase, const AnalysisPassResult &Result)
{
    for(auto &Listener : Listeners)
    {
        Listener->notifyPassResult(Phase, Result);
    }
}

void AnalysisPipeline::run(gtirb::Context &Context, gtirb::Module &Module)
{
    AnalysisPass *PreviousPass = nullptr;
    for(auto &Pass : Passes)
    {
        notifyPassBegin(*Pass);
        notifyPassPhase(AnalysisPassPhase::LOAD, Pass->hasLoad());
        if(Pass->hasLoad())
        {
            auto Result = Pass->load(Context, Module, PreviousPass);
            notifyPassResult(AnalysisPassPhase::LOAD, Result);
        }

        // Clear previous pass data
        if(PreviousPass != nullptr)
        {
            PreviousPass->clear();
        }

        if(DatalogAnalysisPass *DatalogPass = dynamic_cast<DatalogAnalysisPass *>(Pass.get()))
        {
            DatalogHints.insert(DatalogPass->getProgram(), DatalogPass->getNameSlug());
        }

        notifyPassPhase(AnalysisPassPhase::ANALYZE);
        auto Result = Pass->analyze(Module);
        notifyPassResult(AnalysisPassPhase::ANALYZE, Result);

        notifyPassPhase(AnalysisPassPhase::TRANSFORM, Pass->hasTransform());
        if(Pass->hasTransform())
        {
            auto Result = Pass->transform(Context, Module);
            notifyPassResult(AnalysisPassPhase::TRANSFORM, Result);
        }

        PreviousPass = Pass.get();
        notifyPassEnd(*Pass);
    }

    // Clear the last pass.
    if(PreviousPass)
    {
        PreviousPass->clear();
    }
}
