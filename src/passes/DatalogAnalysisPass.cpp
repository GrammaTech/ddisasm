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

#include <boost/filesystem.hpp>
namespace fs = boost::filesystem;

#include <gtirb/gtirb.hpp>
#include <gtirb_pprinter/AuxDataUtils.hpp>

#include "../AuxDataSchema.h"
#include "Interpreter.h"

AnalysisPassResult DatalogAnalysisPass::analyze(const gtirb::Module& Module)
{
    if(!DebugDirRoot.empty())
    {
        DatalogIO::writeFacts(getDebugDir(Module) + "/", *Program);
    }

    if(ExecutionMode == DatalogExecutionMode::SYNTHESIZED)
    {
        DatalogIO::setProfilePath(ProfilePath);
    }

    AnalysisPassResult Result = AnalysisPass::analyze(Module);

    if(!DebugDirRoot.empty())
    {
        DatalogIO::writeRelations(getDebugDir(Module) + "/", *Program);
    }

    if(ExecutionMode == DatalogExecutionMode::SYNTHESIZED)
    {
        std::string Err = DatalogIO::clearProfileDB();
        if(!Err.empty())
        {
            Result.Errors.push_back(Err);
            return Result;
        }
    }

    return Result;
}

void DatalogAnalysisPass::analyzeImpl(AnalysisPassResult& Result, const gtirb::Module& Module)
{
    if(ExecutionMode == DatalogExecutionMode::INTERPRETED)
    {
        // Disassemble with the interpreter engine.
        runInterpreter(*Module.getIR(), Module, *Program, InterpreterPath, getDebugDir(Module),
                       LibDir, ProfilePath, ThreadCount);
    }
    else
    {
        // Disassemble with the compiled, synthesized program.
        Program->setNumThreads(ThreadCount);
        bool pruneImdtRels = !WriteSouffleOutputs && DebugDirRoot.empty();
        try
        {
            Program->runAll("", "", false, pruneImdtRels);
        }
        catch(std::exception& e)
        {
            Result.Errors.push_back(e.what());
        }
    }
}

void addRelationsToMap(souffle::SouffleProgram& Program,
                       const std::vector<souffle::Relation*>& Relations,
                       std::map<std::string, std::tuple<std::string, std::string>>& Map,
                       const std::string& Namespace)
{
    for(souffle::Relation* Relation : Relations)
    {
        if(Relation->getArity() == 0)
        {
            continue;
        }

        std::stringstream Type;
        DatalogIO::serializeType(Type, Relation);

        // Write CSV to buffer.
        std::stringstream Csv;
        DatalogIO::writeRelation(Csv, Program, Relation);

        // TODO: Compress CSV.
        Map[Namespace + "." + Relation->getName()] = {Type.str(), Csv.str()};
    }
}

void writeRelationAuxdata(souffle::SouffleProgram& Program, gtirb::Module& Module,
                          const std::string& Namespace)
{
    auto Facts = aux_data::util::getOrDefault<gtirb::schema::SouffleFacts>(Module);
    auto Outputs = aux_data::util::getOrDefault<gtirb::schema::SouffleOutputs>(Module);

    addRelationsToMap(Program, Program.getInputRelations(), Facts, Namespace);
    addRelationsToMap(Program, Program.getInternalRelations(), Outputs, Namespace);
    addRelationsToMap(Program, Program.getOutputRelations(), Outputs, Namespace);

    Module.addAuxData<gtirb::schema::SouffleFacts>(std::move(Facts));
    Module.addAuxData<gtirb::schema::SouffleOutputs>(std::move(Outputs));
}

void DatalogAnalysisPass::transformImpl(AnalysisPassResult& Result, gtirb::Context& Context,
                                        gtirb::Module& Module)
{
    if(WriteSouffleOutputs)
    {
        writeRelationAuxdata(*Program, Module, getNameSlug());
    }
}

void DatalogAnalysisPass::clear()
{
    Program.reset();
}
