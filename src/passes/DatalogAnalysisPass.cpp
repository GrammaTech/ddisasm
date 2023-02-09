//===- DatalogAnalysisPass.cpp =---------------------------------*- C++ -*-===//
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
#include "DatalogAnalysisPass.h"

#include "Interpreter.h"

#if defined(DDISASM_SOUFFLE_PROFILING)
#include <souffle/profile/ProfileEvent.h>

#include <boost/filesystem.hpp>
namespace fs = boost::filesystem;
#endif

AnalysisPassResult DatalogAnalysisPass::analyze(const gtirb::Module& Module)
{
    if(!DebugDir.empty())
    {
        fs::create_directories(DebugDir);
        Souffle->writeFacts(DebugDir.string() + "/");
    }

#if defined(DDISASM_SOUFFLE_PROFILING)
    if(ExecutionMode == DatalogExecutionMode::SYNTHESIZED)
    {
        souffle::ProfileEventSingleton::instance().setOutputFile(ProfilePath);
    }
#endif

    AnalysisPassResult Result = AnalysisPass::analyze(Module);

    if(!DebugDir.empty())
    {
        Souffle->writeRelations(DebugDir.string() + "/");
    }

#if defined(DDISASM_SOUFFLE_PROFILING)
    if(ExecutionMode == DatalogExecutionMode::SYNTHESIZED)
    {
        souffle::ProfileEventSingleton::instance().stopTimer();
        souffle::ProfileEventSingleton::instance().dump();

        // Clearing the profile path ensures the ProfileEventSingleton
        // destructor does not dump again.
        souffle::ProfileEventSingleton::instance().setOutputFile("");

        // Clear the profile database by loading an empty json file
        // (this is the only way to clear it that Souffle currently exposes)
        fs::path DbFilePath = fs::unique_path();

        std::ofstream DbFile(DbFilePath.string(), std::ios::out);
        if(!DbFile.is_open())
        {
            Result.Errors.push_back("Failed to clear profile data: could not open "
                                    + DbFilePath.string());
            return Result;
        }
        DbFile << "{}\n";
        DbFile.close();

        souffle::ProfileEventSingleton::instance().setDBFromFile(DbFilePath.string());
        fs::remove(DbFilePath);
    }
#endif

    return Result;
}

void DatalogAnalysisPass::analyzeImpl(AnalysisPassResult& Result, const gtirb::Module& Module)
{
    if(ExecutionMode == DatalogExecutionMode::INTERPRETED)
    {
        // Disassemble with the interpreter engine.
        runInterpreter(*Module.getIR(), Module, *Souffle, InterpreterPath, DebugDir.string(),
                       LibDir, ProfilePath, ThreadCount);
    }
    else
    {
        // Disassemble with the compiled, synthesized program.
        Souffle->threads(ThreadCount);
        Souffle->pruneImdtRels = !WriteSouffleOutputs && DebugDir.empty();
        try
        {
            Souffle->run();
        }
        catch(std::exception& e)
        {
            Result.Errors.push_back(e.what());
        }
    }
}

AnalysisPassResult DatalogAnalysisPass::transform(gtirb::Context& Context, gtirb::Module& Module)
{
    std::string Slug;
    if(WriteSouffleOutputs)
    {
        Slug = getNameSlug();
        Souffle->writeFacts(Module, Slug);
    }

    auto Result = AnalysisPass::transform(Context, Module);

    if(WriteSouffleOutputs)
    {
        Souffle->writeRelations(Module, Slug);
    }

    return Result;
}

void DatalogAnalysisPass::readHints(const std::string& Filename)
{
    Souffle->readHintsFile(Filename, getName());
}
