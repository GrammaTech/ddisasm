//===- FunctionInferencePass.cpp --------------------------------*- C++ -*-===//
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

#include <boost/uuid/uuid_generators.hpp>

#include "../AuxDataSchema.h"
#include "../gtirb-decoder/CompositeLoader.h"
#include "../gtirb-decoder/arch/X64Loader.h"
#include "../gtirb-decoder/core/AuxDataLoader.h"
#include "../gtirb-decoder/core/EdgesLoader.h"
#include "../gtirb-decoder/core/InstructionLoader.h"
#include "../gtirb-decoder/core/SymbolicExpressionLoader.h"

void FunctionInferencePass::updateFunctions(gtirb::Context& Context, gtirb::Module& Module,
                                            souffle::SouffleProgram* Program)
{
    auto* SymbolInfo = Module.getAuxData<gtirb::schema::ElfSymbolInfoAD>();

    std::map<gtirb::UUID, std::set<gtirb::UUID>> FunctionEntries;
    std::map<gtirb::Addr, gtirb::UUID> FunctionEntry2function;
    std::map<gtirb::UUID, gtirb::UUID> FunctionNames;
    boost::uuids::random_generator Generator;
    for(auto& Output : *Program->getRelation("function_entry_final"))
    {
        gtirb::Addr FunctionEntry(Output[0]);
        auto BlockRange = Module.findCodeBlocksAt(FunctionEntry);
        if(!BlockRange.empty())
        {
            const gtirb::UUID& EntryBlockUUID = BlockRange.begin()->getUUID();
            gtirb::UUID FunctionUUID = Generator();
            FunctionEntry2function[FunctionEntry] = FunctionUUID;
            FunctionEntries[FunctionUUID].insert(EntryBlockUUID);

            const auto& Symbols = Module.findSymbols(FunctionEntry);

            auto It = Module.findSymbols(FunctionEntry);
            if(It.empty())
            {
                // Create a new label for the function entry.
                std::stringstream Label;
                Label << ".L_" << std::hex << static_cast<uint64_t>(FunctionEntry);
                gtirb::Symbol* Symbol = Module.addSymbol(Context, FunctionEntry, Label.str());

                // Map function to symbol and create new symbol information.
                FunctionNames.insert({FunctionUUID, Symbol->getUUID()});
                if(SymbolInfo)
                {
                    ElfSymbolInfo Info = {0, "FUNC", "LOCAL", "DEFAULT", 0};
                    SymbolInfo->insert({Symbol->getUUID(), Info});
                }

                // Connect new symbol to the code-block.
                if(auto Found = Module.findCodeBlocksAt(FunctionEntry); !Found.empty())
                {
                    gtirb::CodeBlock& CodeBlock = Found.front();
                    Symbol->setReferent(&CodeBlock);
                }
            }
            else if(SymbolInfo)
            {
                // Aggregate candidate symbols.
                std::vector<std::tuple<const gtirb::Symbol*, std::string, std::string>> Candidates;
                for(auto& Symbol : It)
                {
                    if(const auto& Found = SymbolInfo->find(Symbol.getUUID());
                       Found != SymbolInfo->end())
                    {
                        std::string& Type = std::get<1>(Found->second);
                        std::string& Binding = std::get<2>(Found->second);
                        Candidates.push_back({&Symbol, Type, Binding});
                    }
                }
                // Select best candidate symbols.
                auto Found = std::min_element(
                    Candidates.begin(), Candidates.end(),
                    [](const std::tuple<const gtirb::Symbol*, std::string, std::string>& S1,
                       const std::tuple<const gtirb::Symbol*, std::string, std::string>& S2) {
                        auto& [Symbol1, Type1, Binding1] = S1;
                        auto& [Symbol2, Type2, Binding2] = S2;
                        // Prefer symbols of type FUNC.
                        if(Type1 == "FUNC" && Type2 != "FUNC")
                            return true;
                        // Prefer GLOBAL FUNC symbols to LOCAL FUNC symbols.
                        if(Binding1 == "GLOBAL" && Binding2 != "GLOBAL")
                            return true;
                        // Prefer symbols without underscore prefixes.
                        const std::string &Name1 = Symbol1->getName(), &Name2 = Symbol2->getName();
                        if(Name1.substr(0, 1) != "_" && Name2.substr(0, 1) == "_")
                            return true;
                        return false;
                    });
                assert(Found != Candidates.end() && "Expected candidate function symbols.");
                FunctionNames.insert({FunctionUUID, std::get<0>(*Found)->getUUID()});
            }
            else
            {
                // Use an arbitrary symbol at this address as the function label.
                gtirb::Symbol* Symbol = &*It.begin();
                FunctionNames.insert({FunctionUUID, Symbol->getUUID()});
            }
        }
    }
    std::map<gtirb::UUID, std::set<gtirb::UUID>> FunctionBlocks;
    for(auto& Output : *Program->getRelation("in_function_final"))
    {
        gtirb::Addr BlockAddr(Output[0]), FunctionEntryAddr(Output[1]);
        auto BlockRange = Module.findCodeBlocksOn(BlockAddr);
        if(!BlockRange.empty())
        {
            gtirb::CodeBlock* Block = &*BlockRange.begin();
            gtirb::UUID FunctionEntryUUID = FunctionEntry2function[FunctionEntryAddr];
            FunctionBlocks[FunctionEntryUUID].insert(Block->getUUID());
        }
    }
    Module.removeAuxData<gtirb::schema::FunctionEntries>();
    Module.removeAuxData<gtirb::schema::FunctionBlocks>();
    Module.removeAuxData<gtirb::schema::FunctionNames>();
    Module.addAuxData<gtirb::schema::FunctionEntries>(std::move(FunctionEntries));
    Module.addAuxData<gtirb::schema::FunctionBlocks>(std::move(FunctionBlocks));
    Module.addAuxData<gtirb::schema::FunctionNames>(std::move(FunctionNames));
}

void FunctionInferencePass::computeFunctions(gtirb::Context& Context, gtirb::Module& Module,
                                             unsigned int NThreads)
{
    // Build GTIRB loader.
    CompositeLoader Loader("souffle_function_inference");
    Loader.add(BlocksLoader);
    Loader.add(CfgLoader);
    Loader.add(SymbolicExpressionLoader);

    // TODO: Add support for ARM64 prologues.
    if(Module.getISA() == gtirb::ISA::X64)
        Loader.add<CodeBlockLoader<X64Loader>>();

    if(Module.getAuxData<gtirb::schema::Padding>())
        Loader.add(PaddingLoader{&Context});
    if(Module.getAuxData<gtirb::schema::CfiDirectives>())
        Loader.add(FdeEntriesLoader{&Context});
    if(Module.getAuxData<gtirb::schema::FunctionEntries>())
        Loader.add(FunctionEntriesLoader{&Context});

    // Load GTIRB and build program.
    std::optional<DatalogProgram> FunctionInference = Loader.load(Module);
    if(!FunctionInference)
    {
        std::cerr << "Could not create souffle_function_inference program" << std::endl;
        exit(1);
    }

    // Run function inference analysis.
    FunctionInference->threads(NThreads);
    FunctionInference->run();

    if(DebugDir)
    {
        FunctionInference->writeFacts(*DebugDir);
        FunctionInference->writeRelations(*DebugDir);
    }

    updateFunctions(Context, Module, FunctionInference->get());
}
