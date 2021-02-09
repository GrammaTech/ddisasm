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
                // Collect FUNC symbols.
                std::set<std::pair<std::string, gtirb::UUID>> Locals;
                std::set<std::pair<std::string, gtirb::UUID>> Globals;
                for(const auto& Symbol : Symbols)
                {
                    if(auto Found = SymbolInfo->find(Symbol.getUUID()); Found != SymbolInfo->end())
                    {
                        if(std::string& Type = std::get<1>(Found->second); Type == "FUNC")
                        {
                            std::string& Binding = std::get<2>(Found->second);
                            if(Binding == "GLOBAL")
                            {
                                Globals.insert(std::make_pair(Symbol.getName(), Symbol.getUUID()));
                            }
                            else
                            {
                                Locals.insert(std::make_pair(Symbol.getName(), Symbol.getUUID()));
                            }
                        }
                    }
                }
                // Prefer GLOBAL symbols if there are any.
                auto& FuncSymbols = Globals.size() > 0 ? Globals : Locals;
                if(FuncSymbols.size() > 0)
                {
                    // Use the first FUNC symbol.
                    FunctionNames.insert({FunctionUUID, (*FuncSymbols.begin()).second});
                }
                else
                {
                    // Use the first non-FUNC symbol.
                    gtirb::Symbol* Symbol = &*It.begin();
                    FunctionNames.insert({FunctionUUID, Symbol->getUUID()});
                }
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
