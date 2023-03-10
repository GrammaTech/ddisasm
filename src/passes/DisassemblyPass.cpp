//===- DisassemblyPass.cpp =-------------------------------------*- C++ -*-===//
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
#include "DisassemblyPass.h"

#include "../gtirb-decoder/CompositeLoader.h"
#include "../gtirb-decoder/Relations.h"
#include "../gtirb-decoder/core/ModuleLoader.h"
#include "Disassembler.h"

std::map<DisassemblyPass::Target, DisassemblyPass::Factory>& DisassemblyPass::loaders()
{
    static std::map<Target, Factory> Loaders;
    return Loaders;
}

void DisassemblyPass::loadImpl(AnalysisPassResult& Result, const gtirb::Context& Context,
                               const gtirb::Module& Module, AnalysisPass* PreviousPass)
{
    auto Target = std::make_tuple(Module.getFileFormat(), Module.getISA(), Module.getByteOrder());
    auto Factories = loaders();
    if(auto It = Factories.find(Target); It != Factories.end())
    {
        auto Loader = (It->second)();
        Program = Loader.load(Module);
    }
    else
    {
        std::stringstream StrBuilder;
        StrBuilder << Module.getName() << ": "
                   << "Unsupported binary target: " << binaryFormat(Module.getFileFormat()) << "-"
                   << binaryISA(Module.getISA()) << "-" << binaryEndianness(Module.getByteOrder())
                   << "\n\nAvailable targets:\n";

        for(auto [Target, Loader] : Factories)
        {
            auto [FileFormat, Arch, ByteOrder] = Target;
            StrBuilder << "\t" << binaryFormat(FileFormat) << "-" << binaryISA(Arch) << "-"
                       << binaryEndianness(ByteOrder) << "\n";
        }
        Result.Errors.push_back(StrBuilder.str());
    }

    if(NoCfiDirectives)
    {
        std::vector<std::string> Options;
        Options.push_back("no-cfi-directives");
        relations::insert(*Program, "option", Options);
    }
}

void DisassemblyPass::transformImpl(AnalysisPassResult& Result, gtirb::Context& Context,
                                    gtirb::Module& Module)
{
    DatalogAnalysisPass::transformImpl(Result, Context, Module);

    disassembleModule(Context, Module, *Program, SelfDiagnose);
    performSanityChecks(Result, *Program, SelfDiagnose, IgnoreErrors);
}
