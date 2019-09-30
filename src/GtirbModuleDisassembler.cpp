//===- GtirbModuleDisassembler.cpp ------------------------------*- C++ -*-===//
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

#include "GtirbModuleDisassembler.h"
#include <boost/uuid/uuid_generators.hpp>
#include "DlOperandTable.h"

// souffle uses a signed integer for all numbers (either 32 or 64 bits
// dependin on compilation flags). Allow conversion to other types.
souffle::tuple &operator>>(souffle::tuple &t, uint64_t &number)
{
    int64_t x;
    t >> x;
    number = x;
    return t;
}

souffle::tuple &operator>>(souffle::tuple &t, gtirb::Addr &ea)
{
    uint64_t x;
    t >> x;
    ea = gtirb::Addr(x);
    return t;
}

souffle::tuple &operator>>(souffle::tuple &t, uint8_t &byte)
{
    int64_t x;
    t >> x;
    assert(x >= 0);
    assert(x < 256);
    byte = x;
    return t;
}

struct DecodedInstruction
{
    gtirb::Addr EA;
    uint64_t Size;
    std::map<uint64_t, std::variant<ImmOp, IndirectOp>> Operands;
    int64_t immediateOffset;
    int64_t displacementOffset;
};

std::map<gtirb::Addr, DecodedInstruction> recoverInstructions(souffle::SouffleProgram *prog)
{
    std::map<uint64_t, ImmOp> Immediates;
    for(auto &output : *prog->getRelation("op_immediate"))
    {
        uint64_t operandCode;
        ImmOp immediate;
        output >> operandCode >> immediate;
        Immediates[operandCode] = immediate;
    };
    std::map<uint64_t, IndirectOp> Indirects;
    for(auto &output : *prog->getRelation("op_indirect"))
    {
        uint64_t operandCode, size;
        IndirectOp indirect;
        output >> operandCode >> indirect.reg1 >> indirect.reg2 >> indirect.reg3
            >> indirect.multiplier >> indirect.displacement >> size;
        Indirects[operandCode] = indirect;
    };
    std::map<gtirb::Addr, DecodedInstruction> insns;
    for(auto &output : *prog->getRelation("instruction_complete"))
    {
        DecodedInstruction insn;
        gtirb::Addr EA;
        std::string prefix, opcode;
        output >> EA >> insn.Size >> prefix >> opcode;
        for(size_t i = 1; i <= 4; i++)
        {
            uint64_t operandIndex;
            output >> operandIndex;
            auto foundImmediate = Immediates.find(operandIndex);
            if(foundImmediate != Immediates.end())
                insn.Operands[i] = foundImmediate->second;
            else
            {
                auto foundIndirect = Indirects.find(operandIndex);
                if(foundIndirect != Indirects.end())
                    insn.Operands[i] = foundIndirect->second;
            }
        }
        output >> insn.immediateOffset >> insn.displacementOffset;
        insns[EA] = insn;
    }
    return insns;
}

struct CodeInBlock
{
    CodeInBlock(souffle::tuple &tuple)
    {
        assert(tuple.size() == 2);

        tuple >> EA >> BlockAddress;
    };

    gtirb::Addr EA{0};
    gtirb::Addr BlockAddress{0};
};

struct BlockInformation
{
    BlockInformation(gtirb::Addr ea) : EA(ea)
    {
    }

    BlockInformation(souffle::tuple &tuple)
    {
        assert(tuple.size() == 3);
        tuple >> EA >> size;
    };

    gtirb::Addr EA{0};
    uint64_t size{0};
};

struct PLTReference
{
    PLTReference(gtirb::Addr ea) : EA(ea)
    {
    }

    PLTReference(souffle::tuple &tuple)
    {
        assert(tuple.size() == 2);
        tuple >> EA >> Name;
    };

    std::string Name;
    gtirb::Addr EA{0};
};

struct MovedLabel
{
    MovedLabel(gtirb::Addr ea) : EA(ea)
    {
    }

    MovedLabel(souffle::tuple &tuple)
    {
        assert(tuple.size() == 4);
        tuple >> EA >> OperandIndex >> Address1 >> Address2;
    };

    gtirb::Addr EA{0};
    uint64_t OperandIndex{0};
    int64_t Address1{0};
    int64_t Address2{0};
};

struct MovedDataLabel
{
    MovedDataLabel(gtirb::Addr ea) : EA(ea)
    {
    }

    MovedDataLabel(souffle::tuple &tuple)
    {
        assert(tuple.size() == 4);
        tuple >> EA >> Size >> Address1 >> Address2;
    };

    gtirb::Addr EA{0};
    uint64_t Size{0};
    int64_t Address1{0};
    int64_t Address2{0};
};

struct SymbolicExpression
{
    SymbolicExpression(souffle::tuple &tuple)
    {
        assert(tuple.size() == 4);
        tuple >> EA >> OperandIndex;
    };

    gtirb::Addr EA{0};
    uint64_t OperandIndex{0};
};

struct BlockPoints
{
    BlockPoints(souffle::tuple &tuple)
    {
        assert(tuple.size() == 4);
        tuple >> Address >> Predecessor >> Importance >> Why;
    };

    gtirb::Addr Address{0};
    gtirb::Addr Predecessor{0};
    int64_t Importance{0};
    std::string Why;
};

template <typename T>
using VectorByEA = boost::multi_index_container<
    T, boost::multi_index::indexed_by<boost::multi_index::ordered_non_unique<
           boost::multi_index::member<T, decltype(T::EA), &T::EA>>>>;

struct SymbolicInfo
{
    VectorByEA<MovedLabel> MovedLabels;
    VectorByEA<SymbolicExpression> SymbolicExpressions;
};

struct SymbolicData
{
    SymbolicData(gtirb::Addr ea) : EA(ea)
    {
    }

    SymbolicData(souffle::tuple &tuple)
    {
        assert(tuple.size() == 3);
        tuple >> EA >> Size >> GroupContent;
    };

    gtirb::Addr EA{0};
    uint64_t Size{0};
    gtirb::Addr GroupContent{0};
};

struct SymbolicExpr
{
    SymbolicExpr(gtirb::Addr ea) : EA(ea)
    {
    }

    SymbolicExpr(souffle::tuple &tuple)
    {
        assert(tuple.size() == 4);
        tuple >> EA >> Size >> Symbol >> Addend;
    };

    gtirb::Addr EA{0};
    uint64_t Size{0};
    std::string Symbol;
    int64_t Addend{0};
};

struct SymbolMinusSymbol
{
    SymbolMinusSymbol(gtirb::Addr ea) : EA(ea)
    {
    }

    SymbolMinusSymbol(souffle::tuple &tuple)
    {
        assert(tuple.size() == 4);

        tuple >> EA >> Size >> Symbol1 >> Symbol2;
    };

    gtirb::Addr EA{0};
    uint64_t Size;
    gtirb::Addr Symbol1{0};
    gtirb::Addr Symbol2{0};
};

struct StringDataObject
{
    StringDataObject(gtirb::Addr ea) : EA(ea)
    {
    }

    StringDataObject(souffle::tuple &tuple)
    {
        assert(tuple.size() == 2);

        tuple >> EA >> End;
    };

    gtirb::Addr EA{0};
    gtirb::Addr End{0};
};

struct SymbolSpecialType
{
    SymbolSpecialType(gtirb::Addr ea) : EA(ea)
    {
    }

    SymbolSpecialType(souffle::tuple &tuple)
    {
        assert(tuple.size() == 2);

        tuple >> EA >> Type;
    };

    gtirb::Addr EA{0};
    std::string Type;
};

template <typename T>
std::vector<T> convertRelation(const std::string &relation, souffle::SouffleProgram *prog)
{
    std::vector<T> result;
    for(auto &output : *prog->getRelation(relation))
    {
        result.emplace_back(output);
    }
    return result;
}

template <>
std::vector<gtirb::Addr> convertRelation<gtirb::Addr>(const std::string &relation,
                                                      souffle::SouffleProgram *prog)
{
    std::vector<gtirb::Addr> result;
    for(auto &output : *prog->getRelation(relation))
    {
        result.emplace_back(output[0]);
    };
    return result;
}

template <typename Container, typename Elem>
Container convertSortedRelation(const std::string &relation, souffle::SouffleProgram *prog)
{
    Container result;
    for(auto &output : *prog->getRelation(relation))
    {
        Elem elem(output);
        result.insert(elem);
    }
    return result;
}

void buildInferredSymbols(gtirb::Context &context, gtirb::Module &module,
                          souffle::SouffleProgram *prog)
{
    for(auto &output : *prog->getRelation("inferred_symbol_name"))
    {
        gtirb::Addr addr;
        std::string name;
        output >> addr >> name;
        if(!module.findSymbols(name))
            gtirb::emplaceSymbol(module, context, addr, name);
    }
}

// auxiliary function to get a symbol with an address and name
gtirb::Symbol *findSymbol(gtirb::Module &module, gtirb::Addr ea, std::string name)
{
    auto found = module.findSymbols(ea);
    for(gtirb::Symbol &symbol : found)
    {
        if(symbol.getName() == name)
            return &symbol;
    }
    return nullptr;
}

// Build a first version of the SymbolForwarding table with copy relocations
void buildSymbolForwarding(gtirb::Context &context, gtirb::Module &module,
                           souffle::SouffleProgram *prog)
{
    std::map<gtirb::UUID, gtirb::UUID> symbolForwarding;
    for(auto &output : *prog->getRelation("relocation"))
    {
        gtirb::Addr ea;
        uint64_t offset;
        std::string type, name;
        output >> ea >> type >> name >> offset;
        if(type == "R_X86_64_COPY")
        {
            gtirb::Symbol *copySymbol = findSymbol(module, ea, name);
            if(copySymbol)
            {
                gtirb::Symbol *realSymbol = gtirb::emplaceSymbol(module, context, name);
                gtirb::renameSymbol(module, *copySymbol, name + "_copy");
                symbolForwarding[copySymbol->getUUID()] = realSymbol->getUUID();
            }
        }
    }
    module.addAuxData("symbolForwarding", std::move(symbolForwarding));
}

// Expand the SymbolForwarding table with plt references
void expandSymbolForwarding(gtirb::Module &module, souffle::SouffleProgram *prog)
{
    auto *symbolForwarding =
        module.getAuxData<std::map<gtirb::UUID, gtirb::UUID>>("symbolForwarding");
    for(auto &output : *prog->getRelation("plt_block"))
    {
        gtirb::Addr ea;
        std::string name;
        output >> ea >> name;
        // the inference of plt_block guarantees that there is at most one
        // destination symbol for each source
        auto foundSrc = module.findSymbols(ea);
        auto foundDest = module.findSymbols(name);
        for(gtirb::Symbol &src : foundSrc)
        {
            for(gtirb::Symbol &dest : foundDest)
            {
                (*symbolForwarding)[src.getUUID()] = dest.getUUID();
            }
        }
    }
    for(auto &output : *prog->getRelation("got_reference"))
    {
        gtirb::Addr ea;
        std::string name;
        output >> ea >> name;
        auto foundSrc = module.findSymbols(ea);
        auto foundDest = module.findSymbols(name);
        for(gtirb::Symbol &src : foundSrc)
        {
            for(gtirb::Symbol &dest : foundDest)
            {
                (*symbolForwarding)[src.getUUID()] = dest.getUUID();
            }
        }
    }
}

bool isNullReg(const std::string &reg)
{
    return reg == "NONE";
}

std::string getLabel(uint64_t ea)
{
    std::stringstream ss;
    ss << ".L_" << std::hex << ea;
    return ss.str();
}

gtirb::Symbol *getSymbol(gtirb::Context &context, gtirb::Module &module, gtirb::Addr ea)
{
    const auto *symbolForwarding =
        module.getAuxData<std::map<gtirb::UUID, gtirb::UUID>>("symbolForwarding");
    auto found = module.findSymbols(ea);
    if(!found.empty())
    {
        gtirb::Symbol *bestSymbol = &*found.begin();
        for(auto it = found.begin(); it != found.end(); it++)
        {
            auto forwardSymbol = symbolForwarding->find(it->getUUID());
            if(forwardSymbol != symbolForwarding->end())
                bestSymbol = &*it;
        }
        return bestSymbol;
    }
    auto *sym = gtirb::Symbol::Create(context, ea, getLabel(uint64_t(ea)),
                                      gtirb::Symbol::StorageKind::Local);
    module.addSymbol(sym);
    return sym;
}

void buildSymbolicImmediate(gtirb::Context &context, gtirb::Module &module, const gtirb::Addr &ea,
                            const DecodedInstruction &instruction, uint64_t index, ImmOp &immediate,
                            const SymbolicInfo &symbolicInfo)
{
    // Symbol+constant case
    auto rangeMovedLabel = symbolicInfo.MovedLabels.equal_range(ea);
    if(auto movedLabel =
           std::find_if(rangeMovedLabel.first, rangeMovedLabel.second,
                        [index](const auto &element) { return element.OperandIndex == index; });
       movedLabel != rangeMovedLabel.second)
    {
        assert(movedLabel->Address1 == immediate);
        auto diff = movedLabel->Address1 - movedLabel->Address2;
        auto sym = getSymbol(context, module, gtirb::Addr(movedLabel->Address2));
        module.addSymbolicExpression(ea + instruction.immediateOffset,
                                     gtirb::SymAddrConst{diff, sym});
        return;
    }
    // Symbol+0 case
    auto range = symbolicInfo.SymbolicExpressions.equal_range(ea);
    if(std::find_if(range.first, range.second,
                    [index](const auto &element) { return element.OperandIndex == index; })
       != range.second)
    {
        auto sym = getSymbol(context, module, gtirb::Addr(immediate));
        module.addSymbolicExpression(ea + instruction.immediateOffset, gtirb::SymAddrConst{0, sym});
        return;
    }
}

void buildSymbolicIndirect(gtirb::Context &context, gtirb::Module &module, const gtirb::Addr &ea,
                           const DecodedInstruction &instruction, uint64_t index,
                           IndirectOp &indirect, const SymbolicInfo &symbolicInfo)
{
    // Symbol+constant case
    auto rangeMovedLabel = symbolicInfo.MovedLabels.equal_range(ea);
    if(auto movedLabel =
           std::find_if(rangeMovedLabel.first, rangeMovedLabel.second,
                        [index](const auto &element) { return element.OperandIndex == index; });
       movedLabel != rangeMovedLabel.second)
    {
        auto diff = movedLabel->Address1 - movedLabel->Address2;
        auto sym = getSymbol(context, module, gtirb::Addr(movedLabel->Address2));
        module.addSymbolicExpression(ea + instruction.displacementOffset,
                                     gtirb::SymAddrConst{diff, sym});
        return;
    }
    // Symbol+0 case
    auto range = symbolicInfo.SymbolicExpressions.equal_range(ea);
    if(std::find_if(range.first, range.second,
                    [index](const auto &element) { return element.OperandIndex == index; })
       != range.second)
    {
        if(indirect.reg2 == std::string{"RIP"} && indirect.multiplier == 1
           && isNullReg(indirect.reg1) && isNullReg(indirect.reg3))
        {
            auto address = ea + indirect.displacement + instruction.Size;
            auto sym = getSymbol(context, module, address);
            module.addSymbolicExpression(ea + instruction.displacementOffset,
                                         gtirb::SymAddrConst{0, sym});
        }
        else
        {
            auto sym = getSymbol(context, module, gtirb::Addr(indirect.displacement));
            module.addSymbolicExpression(ea + instruction.displacementOffset,
                                         gtirb::SymAddrConst{0, sym});
        }
    }
}

void buildCodeSymbolicInformation(gtirb::Context &context, gtirb::Module &module,
                                  souffle::SouffleProgram *prog)
{
    auto codeInBlock = convertRelation<CodeInBlock>("code_in_refined_block", prog);
    SymbolicInfo symbolicInfo{
        convertSortedRelation<VectorByEA<MovedLabel>, MovedLabel>("moved_label", prog),
        convertSortedRelation<VectorByEA<SymbolicExpression>, SymbolicExpression>(
            "symbolic_operand", prog)};
    std::map<gtirb::Addr, DecodedInstruction> decodedInstructions = recoverInstructions(prog);

    for(auto &cib : codeInBlock)
    {
        const auto inst = decodedInstructions.find(cib.EA);
        assert(inst != decodedInstructions.end());
        for(auto &op : inst->second.Operands)
        {
            if(auto *immediate = std::get_if<ImmOp>(&op.second))
                buildSymbolicImmediate(context, module, inst->first, inst->second, op.first,
                                       *immediate, symbolicInfo);
            if(auto *indirect = std::get_if<IndirectOp>(&op.second))
                buildSymbolicIndirect(context, module, inst->first, inst->second, op.first,
                                      *indirect, symbolicInfo);
        }
    }
}

void buildCodeBlocks(gtirb::Context &context, gtirb::Module &module, souffle::SouffleProgram *prog)
{
    auto blockInformation = convertSortedRelation<VectorByEA<BlockInformation>, BlockInformation>(
        "block_information", prog);
    for(auto &output : *prog->getRelation("refined_block"))
    {
        gtirb::Addr blockAddress;
        output >> blockAddress;
        uint64_t size = blockInformation.find(blockAddress)->size;
        emplaceBlock(module, context, blockAddress, size);
    }
}

// Create DataObjects for labeled objects in the BSS sections, without adding
// data to the ImageByteMap.

void buildBSS(gtirb::Context &context, gtirb::Module &module, souffle::SouffleProgram *prog)
{
    std::vector<gtirb::Addr> bssData = convertRelation<gtirb::Addr>("bss_data", prog);
    std::sort(bssData.begin(), bssData.end());

    for(auto &output : *prog->getRelation("bss_section"))
    {
        std::string sectionName;
        output >> sectionName;
        const auto bss_section = module.findSection(sectionName);
        if(bss_section == module.section_by_name_end())
            continue;
        // for each bss section we divide in data objects according to the bss_data markers that
        // fall within the range of the section
        auto beginning =
            std::lower_bound(bssData.begin(), bssData.end(), bss_section->getAddress());
        // end points to the address at the end of the bss section
        auto end = std::lower_bound(bssData.begin(), bssData.end(), addressLimit(*bss_section));
        for(auto i = beginning; i != end; ++i)
        {
            auto next = i;
            next++;
            auto *d = gtirb::DataObject::Create(context, *i, *next - *i);
            module.addData(d);
        }
    }
}

void buildDataGroups(gtirb::Context &context, gtirb::Module &module, souffle::SouffleProgram *prog)
{
    auto symbolicData =
        convertSortedRelation<VectorByEA<SymbolicData>, SymbolicData>("symbolic_data", prog);
    auto movedDataLabels =
        convertSortedRelation<VectorByEA<MovedDataLabel>, MovedDataLabel>("moved_data_label", prog);
    auto symbolicExprs = convertSortedRelation<VectorByEA<SymbolicExpr>, SymbolicExpr>(
        "symbolic_expr_from_relocation", prog);
    auto symbolMinusSymbol =
        convertSortedRelation<VectorByEA<SymbolMinusSymbol>, SymbolMinusSymbol>(
            "symbol_minus_symbol", prog);

    auto dataStrings =
        convertSortedRelation<VectorByEA<StringDataObject>, StringDataObject>("string", prog);
    auto symbolSpecialTypes =
        convertSortedRelation<VectorByEA<SymbolSpecialType>, SymbolSpecialType>(
            "symbol_special_encoding", prog);
    std::map<gtirb::UUID, std::string> typesTable;

    for(auto &output : *prog->getRelation("non_zero_data_section"))
    {
        std::string sectionName;
        output >> sectionName;
        auto foundSection = module.findSection(sectionName);
        if(foundSection != module.section_by_name_end())
        {
            gtirb::Section &s = *foundSection;
            auto limit = addressLimit(s);
            for(auto currentAddr = s.getAddress(); currentAddr < limit; currentAddr++)
            {
                // undefined symbol
                const auto symbolicExpr = symbolicExprs.find(currentAddr);
                if(symbolicExpr != symbolicExprs.end())
                {
                    auto *d = gtirb::DataObject::Create(context, currentAddr, symbolicExpr->Size);
                    module.addData(d);
                    auto foundSymbol = module.findSymbols(symbolicExpr->Symbol);
                    if(foundSymbol.begin() != foundSymbol.end())
                        module.addSymbolicExpression(
                            currentAddr,
                            gtirb::SymAddrConst{symbolicExpr->Addend, &*foundSymbol.begin()});
                    currentAddr += (symbolicExpr->Size) - 1;
                    continue;
                }
                // symbol+constant
                const auto movedDataLabel = movedDataLabels.find(currentAddr);
                if(movedDataLabel != movedDataLabels.end())
                {
                    auto *d = gtirb::DataObject::Create(context, currentAddr, movedDataLabel->Size);
                    module.addData(d);
                    auto diff = movedDataLabel->Address1 - movedDataLabel->Address2;
                    auto sym = getSymbol(context, module, gtirb::Addr(movedDataLabel->Address2));
                    module.addSymbolicExpression(currentAddr, gtirb::SymAddrConst{diff, sym});
                    const auto specialType = symbolSpecialTypes.find(currentAddr);
                    if(specialType != symbolSpecialTypes.end())
                        typesTable[d->getUUID()] = specialType->Type;
                    currentAddr += (movedDataLabel->Size) - 1;
                    continue;
                }
                // symbol+0
                const auto symbolic = symbolicData.find(currentAddr);
                if(symbolic != symbolicData.end())
                {
                    auto *d = gtirb::DataObject::Create(context, currentAddr, symbolic->Size);
                    module.addData(d);
                    auto sym = getSymbol(context, module, symbolic->GroupContent);
                    module.addSymbolicExpression(currentAddr, gtirb::SymAddrConst{0, sym});
                    const auto specialType = symbolSpecialTypes.find(currentAddr);
                    if(specialType != symbolSpecialTypes.end())
                        typesTable[d->getUUID()] = specialType->Type;
                    currentAddr += (symbolic->Size - 1);
                    continue;
                }
                // symbol-symbol
                const auto symMinusSym = symbolMinusSymbol.find(currentAddr);
                if(symMinusSym != symbolMinusSymbol.end())
                {
                    auto *d = gtirb::DataObject::Create(context, currentAddr, symMinusSym->Size);
                    module.addData(d);
                    module.addSymbolicExpression(
                        gtirb::Addr(currentAddr),
                        gtirb::SymAddrAddr{1, 0, getSymbol(context, module, symMinusSym->Symbol2),
                                           getSymbol(context, module, symMinusSym->Symbol1)});
                    const auto specialType = symbolSpecialTypes.find(currentAddr);
                    if(specialType != symbolSpecialTypes.end())
                        typesTable[d->getUUID()] = specialType->Type;
                    currentAddr += (symMinusSym->Size - 1);
                    continue;
                }
                // string
                const auto str = dataStrings.find(currentAddr);
                if(str != dataStrings.end())
                {
                    auto *d =
                        gtirb::DataObject::Create(context, currentAddr, str->End - currentAddr);
                    module.addData(d);
                    typesTable[d->getUUID()] = std::string{"string"};

                    // Because the loop is going to increment this counter, don't skip a byte.
                    currentAddr = str->End - 1;
                    continue;
                }
                // Store raw data
                auto *d = gtirb::DataObject::Create(context, currentAddr, 1);
                module.addData(d);
            }
        }
    }
    buildBSS(context, module, prog);
    module.addAuxData("encodings", std::move(typesTable));
}

void connectSymbolsToDataGroups(gtirb::Module &module)
{
    std::for_each(module.data_begin(), module.data_end(), [&module](auto &d) {
        auto found = module.findSymbols(d.getAddress());
        std::for_each(found.begin(), found.end(),
                      [&d, &module](auto &sym) { gtirb::setReferent(module, sym, &d); });
    });
}

void connectSymbolsToBlocks(gtirb::Module &module)
{
    auto &cfg = module.getCFG();
    for(auto &block : blocks(cfg))
    {
        for(auto &symbol : module.findSymbols(block.getAddress()))
            gtirb::setReferent(module, symbol, &block);
    }
}

void buildFunctions(gtirb::Module &module, souffle::SouffleProgram *prog)
{
    std::map<gtirb::UUID, std::set<gtirb::UUID>> functionEntries;
    std::map<gtirb::Addr, gtirb::UUID> functionEntry2function;
    boost::uuids::random_generator generator;
    for(auto &output : *prog->getRelation("function_entry2"))
    {
        gtirb::Addr functionEntry;
        output >> functionEntry;
        auto blockRange = module.findBlock(functionEntry);
        if(blockRange.begin() != blockRange.end())
        {
            const gtirb::UUID &entryBlockUUID = blockRange.begin()->getUUID();
            gtirb::UUID functionUUID = generator();
            functionEntry2function[functionEntry] = functionUUID;
            functionEntries[functionUUID].insert(entryBlockUUID);
        }
    }

    std::map<gtirb::UUID, std::set<gtirb::UUID>> functionBlocks;
    for(auto &output : *prog->getRelation("in_function"))
    {
        gtirb::Addr blockAddr, functionEntryAddr;
        output >> blockAddr >> functionEntryAddr;
        auto blockRange = module.findBlock(blockAddr);
        if(blockRange.begin() != blockRange.end())
        {
            gtirb::Block *block = &*blockRange.begin();
            gtirb::UUID functionEntryUUID = functionEntry2function[functionEntryAddr];
            functionBlocks[functionEntryUUID].insert(block->getUUID());
        }
    }
    module.addAuxData("functionEntries", std::move(functionEntries));
    module.addAuxData("functionBlocks", std::move(functionBlocks));
}

gtirb::EdgeType getEdgeType(const std::string &type)
{
    if(type == "branch")
        return gtirb::EdgeType::Branch;
    if(type == "call")
        return gtirb::EdgeType::Call;
    if(type == "return")
        return gtirb::EdgeType::Return;
    // TODO syscall and sysret
    return gtirb::EdgeType::Fallthrough;
}

void buildCFG(gtirb::Context &context, gtirb::Module &module, souffle::SouffleProgram *prog)
{
    auto &cfg = module.getCFG();
    for(auto &output : *prog->getRelation("cfg_edge"))
    {
        gtirb::Addr srcAddr, destAddr;
        std::string conditional, indirect, type;
        output >> srcAddr >> destAddr >> conditional >> indirect >> type;

        // ddisasm guarantees that these blocks exist
        const gtirb::Block *src = &*module.findBlock(srcAddr).begin();
        const gtirb::Block *dest = &*module.findBlock(destAddr).begin();

        auto isConditional = conditional == "true" ? gtirb::ConditionalEdge::OnTrue
                                                   : gtirb::ConditionalEdge::OnFalse;
        auto isIndirect =
            indirect == "true" ? gtirb::DirectEdge::IsIndirect : gtirb::DirectEdge::IsDirect;
        gtirb::EdgeType edgeType = getEdgeType(type);

        auto E = addEdge(src, dest, cfg);
        cfg[*E] = std::make_tuple(isConditional, isIndirect, edgeType);
    }
    auto *topBlock = gtirb::ProxyBlock::Create(context);
    module.addCfgNode(topBlock);
    for(auto &output : *prog->getRelation("cfg_edge_to_top"))
    {
        gtirb::Addr srcAddr;
        std::string conditional, type;
        output >> srcAddr >> conditional >> type;
        const gtirb::Block *src = &*module.findBlock(srcAddr).begin();
        auto isConditional = conditional == "true" ? gtirb::ConditionalEdge::OnTrue
                                                   : gtirb::ConditionalEdge::OnFalse;
        gtirb::EdgeType edgeType = getEdgeType(type);
        auto E = addEdge(src, topBlock, cfg);
        cfg[*E] = std::make_tuple(isConditional, gtirb::DirectEdge::IsIndirect, edgeType);
    }
    for(auto &output : *prog->getRelation("cfg_edge_to_symbol"))
    {
        gtirb::Addr srcAddr;
        std::string symbolName;
        output >> srcAddr >> symbolName;
        const gtirb::Block *src = &*module.findBlock(srcAddr).begin();
        gtirb::Symbol &symbol = *module.findSymbols(symbolName).begin();
        gtirb::ProxyBlock *externalBlock = symbol.getReferent<gtirb::ProxyBlock>();
        // if the symbol does not point to a ProxyBlock yet, we create it
        if(!externalBlock)
        {
            externalBlock = gtirb::ProxyBlock::Create(context);
            module.addCfgNode(externalBlock);
            gtirb::setReferent(module, symbol, externalBlock);
        }
        auto E = addEdge(src, externalBlock, cfg);
        cfg[*E] = std::make_tuple(gtirb::ConditionalEdge::OnFalse, gtirb::DirectEdge::IsIndirect,
                                  gtirb::EdgeType::Branch);
    }
}

// In general, it is expected that findOffsets returns a vector with zero or one items
// because blocks and data objects typically do not overlap.
std::vector<gtirb::Offset> findOffsets(gtirb::Module &module, gtirb::Addr ea)
{
    std::vector<gtirb::Offset> offsets;
    for(auto &block : module.findBlock(ea))
    {
        offsets.push_back(gtirb::Offset(block.getUUID(), ea - block.getAddress()));
    }
    for(auto &dataObject : module.findData(ea))
    {
        offsets.push_back(gtirb::Offset(dataObject.getUUID(), ea - dataObject.getAddress()));
    }
    return offsets;
}

void updateComment(gtirb::Module &module, std::map<gtirb::Offset, std::string> &comments,
                   gtirb::Addr ea, std::string newComment)
{
    std::vector<gtirb::Offset> matchingOffsets = findOffsets(module, ea);
    for(gtirb::Offset &offset : matchingOffsets)
    {
        auto existing = comments.find(offset);
        if(existing != comments.end())
        {
            existing->second += ", ";
            existing->second += newComment;
        }
        else
            comments[offset] = newComment;
    }
}

void buildCfiDirectives(gtirb::Context &context, gtirb::Module &module,
                        souffle::SouffleProgram *prog)
{
    std::map<gtirb::Offset, std::vector<std::tuple<std::string, std::vector<int64_t>, gtirb::UUID>>>
        cfiDirectives;
    for(auto &output : *prog->getRelation("cfi_directive"))
    {
        gtirb::Addr blockAddr, reference;
        std::string directive;
        uint64_t disp, localIndex;
        int64_t nOperands, op1, op2;
        output >> blockAddr >> disp >> localIndex >> directive >> reference >> nOperands >> op1
            >> op2;
        std::vector<int64_t> operands;
        // cfi_escape directives have a sequence of bytes as operands (the raw bytes of the dwarf
        // instruction). The address 'reference' points to these bytes.
        if(directive == ".cfi_escape")
        {
            for(std::byte byte : module.getImageByteMap().data(reference, nOperands))
            {
                operands.push_back(std::to_integer<int64_t>(byte));
            }
        }
        else
        {
            if(nOperands > 0)
                operands.push_back(op1);
            if(nOperands > 1)
                operands.push_back(op2);
        }

        auto blockRange = module.findBlock(blockAddr);
        if(blockRange.begin() != blockRange.end() && blockAddr == blockRange.begin()->getAddress())
        {
            gtirb::Offset offset(blockRange.begin()->getUUID(), disp);
            if(cfiDirectives[offset].size() < localIndex + 1)
                cfiDirectives[offset].resize(localIndex + 1);

            if(directive != ".cfi_escape" && reference != gtirb::Addr(0))
            {
                // for normal directives (not cfi_escape) the reference points to a symbol.
                gtirb::Symbol *symbol = getSymbol(context, module, reference);
                cfiDirectives[offset][localIndex] =
                    std::make_tuple(directive, operands, symbol->getUUID());
            }
            else
            {
                gtirb::UUID uuid;
                cfiDirectives[offset][localIndex] = std::make_tuple(directive, operands, uuid);
            }
        }
    }
    module.addAuxData("cfiDirectives", std::move(cfiDirectives));
}

void buildComments(gtirb::Module &module, souffle::SouffleProgram *prog, bool selfDiagnose)
{
    std::map<gtirb::Offset, std::string> comments;
    for(auto &output : *prog->getRelation("data_access_pattern"))
    {
        gtirb::Addr ea;
        uint64_t size, multiplier, from;
        output >> ea >> size >> multiplier >> from;
        std::ostringstream newComment;
        newComment << "data_access(" << size << ", " << multiplier << ", " << std::hex << from
                   << std::dec << ")";
        updateComment(module, comments, ea, newComment.str());
    }

    for(auto &output : *prog->getRelation("preferred_data_access"))
    {
        gtirb::Addr ea;
        uint64_t data_access;
        output >> ea >> data_access;
        std::ostringstream newComment;
        newComment << "preferred_data_access(" << std::hex << data_access << std::dec << ")";
        updateComment(module, comments, ea, newComment.str());
    }

    for(auto &output : *prog->getRelation("best_value_reg"))
    {
        gtirb::Addr ea, eaOrigin;
        std::string reg, type;
        int64_t multiplier, offset;
        output >> ea >> reg >> eaOrigin >> multiplier >> offset >> type;
        std::ostringstream newComment;
        newComment << reg << "=X*" << multiplier << "+" << std::hex << offset << std::dec
                   << " type(" << type << ")";
        updateComment(module, comments, ea, newComment.str());
    }

    for(auto &output : *prog->getRelation("value_reg"))
    {
        gtirb::Addr ea;
        std::string reg, reg2;
        int64_t multiplier, offset, ea2;
        output >> ea >> reg >> ea2 >> reg2 >> multiplier >> offset;
        std::ostringstream newComment;
        newComment << reg << "=(" << reg2 << "," << std::hex << ea2 << std::dec << ")*"
                   << multiplier << "+" << std::hex << offset << std::dec;
        updateComment(module, comments, ea, newComment.str());
    }

    for(auto &output : *prog->getRelation("moved_label_class"))
    {
        gtirb::Addr ea;
        std::string type;

        output >> ea >> type;
        std::ostringstream newComment;
        newComment << " moved label-" << type;
        updateComment(module, comments, ea, newComment.str());
    }

    for(auto &output : *prog->getRelation("def_used"))
    {
        gtirb::Addr ea_use;
        int64_t ea_def, index;
        std::string reg;
        output >> ea_def >> reg >> ea_use >> index;
        std::ostringstream newComment;
        newComment << "def(" << reg << ", " << std::hex << ea_def << std::dec << ")";
        updateComment(module, comments, ea_use, newComment.str());
    }
    if(selfDiagnose)
    {
        for(auto &output : *prog->getRelation("false_positive"))
        {
            gtirb::Addr ea;
            output >> ea;
            updateComment(module, comments, ea, "false positive");
        }
        for(auto &output : *prog->getRelation("false_negative"))
        {
            gtirb::Addr ea;
            output >> ea;
            updateComment(module, comments, ea, "false negative");
        }
        for(auto &output : *prog->getRelation("bad_symbol_constant"))
        {
            gtirb::Addr ea;
            int64_t index;
            output >> ea >> index;
            std::ostringstream newComment;
            newComment << "bad_symbol_constant(" << index << ")";
            updateComment(module, comments, ea, newComment.str());
        }
    }
    module.addAuxData("comments", std::move(comments));
}

void disassembleModule(gtirb::Context &context, gtirb::Module &module,
                       souffle::SouffleProgram *prog, bool selfDiagnose)
{
    buildInferredSymbols(context, module, prog);
    buildSymbolForwarding(context, module, prog);
    buildDataGroups(context, module, prog);
    buildCodeBlocks(context, module, prog);
    buildCodeSymbolicInformation(context, module, prog);
    connectSymbolsToDataGroups(module);
    buildCfiDirectives(context, module, prog);
    expandSymbolForwarding(module, prog);
    connectSymbolsToBlocks(module);
    buildFunctions(module, prog);
    buildCFG(context, module, prog);
    buildComments(module, prog, selfDiagnose);
}

void performSanityChecks(souffle::SouffleProgram *prog, bool selfDiagnose)
{
    bool error = false;
    if(selfDiagnose)
    {
        std::cout << "Perfoming self diagnose (this will only give the right results if the target "
                     "program contains all the relocation information)"
                  << std::endl;
        auto falsePositives = prog->getRelation("false_positive");
        if(falsePositives->size() > 0)
        {
            error = true;
            std::cerr << "False positives: " << falsePositives->size() << std::endl;
        }
        auto falseNegatives = prog->getRelation("false_negative");
        if(falseNegatives->size() > 0)
        {
            error = true;
            std::cerr << "False negatives: " << falseNegatives->size() << std::endl;
        }
        auto badSymbolCnt = prog->getRelation("bad_symbol_constant");
        if(badSymbolCnt->size() > 0)
        {
            error = true;
            std::cerr << "Bad symbol constants: " << badSymbolCnt->size() << std::endl;
        }
    }
    auto blockOverlap = prog->getRelation("block_still_overlap");
    if(blockOverlap->size() > 0)
    {
        error = true;
        std::cerr << "The conflicts between the following code blocks could not be resolved:"
                  << std::endl;
        for(auto &output : *blockOverlap)
        {
            uint64_t block1, block2;
            output >> block1 >> block2;
            std::cerr << std::hex << block1 << " - " << block2 << std::dec << std::endl;
        }
    }
    if(error)
    {
        std::cerr << "Aborting" << std::endl;
        exit(1);
    }
    if(selfDiagnose && !error)
        std::cout << "Self diagnose completed: No errors found" << std::endl;
}