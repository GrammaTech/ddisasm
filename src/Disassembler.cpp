//===- Disassembler.cpp -----------------------------------------*- C++ -*-===//
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

#include "Disassembler.h"

#include <boost/uuid/uuid_generators.hpp>

#include "AuxDataSchema.h"
#include "gtirb-decoder/CompositeLoader.h"

using ImmOp = relations::ImmOp;
using IndirectOp = relations::IndirectOp;

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
    byte = static_cast<uint8_t>(x);
    return t;
}

struct DecodedInstruction
{
    gtirb::Addr EA;
    uint64_t Size;
    std::map<uint64_t, std::variant<ImmOp, IndirectOp>> Operands;
    uint64_t immediateOffset;
    uint64_t displacementOffset;
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
        output >> operandCode >> indirect.Reg1 >> indirect.Reg2 >> indirect.Reg3 >> indirect.Mult
            >> indirect.Disp >> size;
        Indirects[operandCode] = indirect;
    };
    std::map<gtirb::Addr, DecodedInstruction> insns;
    for(auto &output : *prog->getRelation("instruction"))
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
    gtirb::Addr Address1{0};
    gtirb::Addr Address2{0};
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
    gtirb::Addr Address1{0};
    gtirb::Addr Address2{0};
};

struct SymbolicExpressionNoOffset
{
    SymbolicExpressionNoOffset(souffle::tuple &tuple)
    {
        assert(tuple.size() == 4);
        tuple >> EA >> OperandIndex >> Dest;
    };

    gtirb::Addr EA{0};
    uint64_t OperandIndex{0};
    gtirb::Addr Dest{0};
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
        assert(tuple.size() == 5);

        tuple >> EA >> Size >> Symbol1 >> Symbol2 >> Scale;
    };

    gtirb::Addr EA{0};
    uint64_t Size;
    gtirb::Addr Symbol1{0};
    gtirb::Addr Symbol2{0};
    uint64_t Scale;
};

struct SymbolicOperandAttribute
{
    explicit SymbolicOperandAttribute(gtirb::Addr A) : EA(A)
    {
    }
    explicit SymbolicOperandAttribute(souffle::tuple &T)
    {
        assert(T.size() == 3);
        T >> EA >> Index >> Type;
    }
    gtirb::Addr EA{0};
    uint64_t Index{0};
    std::string Type{"NONE"};
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

struct SymbolicInfo
{
    VectorByEA<MovedLabel> MovedLabels;
    VectorByEA<SymbolicExpressionNoOffset> SymbolicExpressionNoOffsets;
    VectorByEA<SymbolicExpr> SymbolicExpressionsFromRelocations;
    VectorByEA<SymbolMinusSymbol> SymbolicBaseMinusConst;
    VectorByEA<SymbolicOperandAttribute> SymbolicOperandAttributes;
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

template <typename Container, typename Elem = typename Container::value_type>
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

template <>
std::set<gtirb::Addr> convertSortedRelation<std::set<gtirb::Addr>>(const std::string &relation,
                                                                   souffle::SouffleProgram *prog)
{
    std::set<gtirb::Addr> result;
    for(auto &output : *prog->getRelation(relation))
    {
        result.insert(gtirb::Addr(output[0]));
    };
    return result;
}

static std::string getLabel(uint64_t ea)
{
    std::stringstream ss;
    ss << ".L_" << std::hex << ea;
    return ss.str();
}

void buildInferredSymbols(gtirb::Context &context, gtirb::Module &module,
                          souffle::SouffleProgram *prog)
{
    auto *SymbolInfo = module.getAuxData<gtirb::schema::ElfSymbolInfoAD>();
    auto *SymbolTabIdxInfo = module.getAuxData<gtirb::schema::ElfSymbolTabIdxInfoAD>();
    for(auto &output : *prog->getRelation("inferred_symbol_name"))
    {
        gtirb::Addr addr;
        std::string name;
        std::string scope, type;
        output >> addr >> name >> scope >> type;
        if(!module.findSymbols(name))
        {
            gtirb::Symbol *symbol = module.addSymbol(context, addr, name);
            if(SymbolInfo)
            {
                ElfSymbolInfo Info = {0, type, scope, "DEFAULT", 0};
                SymbolInfo->insert({symbol->getUUID(), Info});
            }
            if(SymbolTabIdxInfo)
            {
                ElfSymbolTabIdxInfo TabIdx = std::vector<std::tuple<std::string, uint64_t>>();
                SymbolTabIdxInfo->insert({symbol->getUUID(), TabIdx});
            }
        }
    }
    // Rename ARM mapping symbols.
    std::vector<gtirb::Symbol *> MappingSymbols;
    for(auto &Symbol : module.symbols())
    {
        std::string Name = Symbol.getName();
        if(Name == "$a" || Name == "$d" || Name.substr(0, 2) == "$t" || Name == "$x")
        {
            MappingSymbols.push_back(&Symbol);
        }
    }
    for(auto *Symbol : MappingSymbols)
    {
        if(std::optional<gtirb::Addr> A = Symbol->getAddress())
        {
            Symbol->setName(getLabel(static_cast<uint64_t>(*A)));
        }
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

// Build a first version of the SymbolForwarding table with copy relocations and
// other ABI-specific artifacts that may be duplicated or reintroduced during
// reassembly.
void buildSymbolForwarding(gtirb::Context &context, gtirb::Module &module,
                           souffle::SouffleProgram *prog)
{
    std::map<gtirb::UUID, gtirb::UUID> symbolForwarding;
    for(auto &output : *prog->getRelation("relocation"))
    {
        gtirb::Addr ea;
        int64_t offset;
        std::string type, name;
        output >> ea >> type >> name >> offset;
        if(type == "COPY")
        {
            gtirb::Symbol *copySymbol = findSymbol(module, ea, name);
            if(copySymbol)
            {
                gtirb::Symbol *realSymbol = module.addSymbol(context, name);
                copySymbol->setName(name + "_copy");
                symbolForwarding[copySymbol->getUUID()] = realSymbol->getUUID();
            }
        }
    }
    for(auto &T : *prog->getRelation("abi_intrinsic"))
    {
        gtirb::Addr EA;
        std::string Name;
        T >> EA >> Name;

        gtirb::Symbol *Symbol = findSymbol(module, EA, Name);
        if(Symbol)
        {
            gtirb::Symbol *NewSymbol = module.addSymbol(context, Name);
            Symbol->setName(Name + "_copy");
            symbolForwarding[Symbol->getUUID()] = NewSymbol->getUUID();
        }
    }
    module.addAuxData<gtirb::schema::SymbolForwarding>(std::move(symbolForwarding));
}

gtirb::SymAttributeSet buildSymbolicExpressionAttributes(gtirb::Addr EA, uint64_t Index,
                                                         const SymbolicInfo &Info)
{
    const static std::map<std::string, gtirb::SymAttribute> AttributeMap = {
        {"Part0", gtirb::SymAttribute::Part0},
        {"Part1", gtirb::SymAttribute::Part1},
        {"Part2", gtirb::SymAttribute::Part2},
        {"Part3", gtirb::SymAttribute::Part3},
        {"GotRef", gtirb::SymAttribute::GotRef},
        {"GotRelPC", gtirb::SymAttribute::GotRelPC},
        {"GotRelGot", gtirb::SymAttribute::GotRelGot},
        {"GotRelAddr", gtirb::SymAttribute::GotRelAddr},
        {"GotPage", gtirb::SymAttribute::GotPage},
        {"GotPageOfst", gtirb::SymAttribute::GotPageOfst},
        {"PltRef", gtirb::SymAttribute::PltRef},
        // FIXME: Replace these with appropriate flags when supported:
        {"TpOff", gtirb::SymAttribute::Part0},
        {"GotOff", gtirb::SymAttribute::Part1},
        {"NtpOff", gtirb::SymAttribute::Part2},
        {":lo12:", gtirb::SymAttribute::Part0},
        {":got_lo12:", gtirb::SymAttribute::Part1},
    };
    gtirb::SymAttributeSet Attributes;

    auto Range = Info.SymbolicOperandAttributes.equal_range(EA);
    for(auto It = Range.first; It != Range.second; It++)
    {
        if(It->Index == Index)
        {
            Attributes.addFlag(AttributeMap.at(It->Type));
        }
    }

    return Attributes;
}

bool isNullReg(const std::string &reg)
{
    return reg == "NONE";
}

gtirb::Symbol *getSymbol(gtirb::Context &context, gtirb::Module &module, gtirb::Addr ea)
{
    const auto *symbolForwarding = module.getAuxData<gtirb::schema::SymbolForwarding>();
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

    gtirb::Symbol *symbol = module.addSymbol(context, ea, getLabel(uint64_t(ea)));

    auto *SymbolInfo = module.getAuxData<gtirb::schema::ElfSymbolInfoAD>();
    if(SymbolInfo)
    {
        ElfSymbolInfo Info = {0, "NONE", "LOCAL", "DEFAULT", 0};
        SymbolInfo->insert({symbol->getUUID(), Info});
    }
    auto *SymbolTabIdxInfo = module.getAuxData<gtirb::schema::ElfSymbolTabIdxInfoAD>();
    if(SymbolTabIdxInfo)
    {
        ElfSymbolTabIdxInfo TabIdx = std::vector<std::tuple<std::string, uint64_t>>();
        SymbolTabIdxInfo->insert({symbol->getUUID(), TabIdx});
    }

    return symbol;
}

// Expand the SymbolForwarding table with plt references
void expandSymbolForwarding(gtirb::Context &context, gtirb::Module &module,
                            souffle::SouffleProgram *prog)
{
    auto *symbolForwarding = module.getAuxData<gtirb::schema::SymbolForwarding>();
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
    // GOT reference that does not point to an external symbol but to a location in the code.
    for(auto &output : *prog->getRelation("got_local_reference"))
    {
        gtirb::Addr ea, dest;

        output >> ea >> dest;
        auto foundSrc = module.findSymbols(ea);
        gtirb::Symbol *destSymbol = getSymbol(context, module, dest);
        for(gtirb::Symbol &src : foundSrc)
        {
            (*symbolForwarding)[src.getUUID()] = destSymbol->getUUID();
        }
    }
}

template <class ExprType, typename... Args>
void addSymbolicExpressionToCodeBlock(gtirb::Module &Module, gtirb::Addr Addr, uint64_t Size,
                                      uint64_t Offset, Args... A)
{
    if(auto it = Module.findCodeBlocksOn(Addr); !it.empty())
    {
        gtirb::CodeBlock &Block = *it.begin();
        gtirb::ByteInterval *ByteInterval = Block.getByteInterval();
        std::optional<gtirb::Addr> BaseAddr = ByteInterval->getAddress();
        assert(BaseAddr && "Found byte interval without address.");
        uint64_t BlockOffset = static_cast<uint64_t>(Addr - *BaseAddr + Offset);
        ByteInterval->addSymbolicExpression<ExprType>(BlockOffset, A...);
        if(auto *Sizes = Module.getAuxData<gtirb::schema::SymbolicExpressionSizes>())
        {
            gtirb::Offset ExpressionOffset = gtirb::Offset(ByteInterval->getUUID(), BlockOffset);
            (*Sizes)[ExpressionOffset] = Size;
        }
    }
}

void buildSymbolicImmediate(gtirb::Context &context, gtirb::Module &module, const gtirb::Addr &ea,
                            const DecodedInstruction &instruction, uint64_t index,
                            [[maybe_unused]] ImmOp &immediate, const SymbolicInfo &symbolicInfo)
{
    gtirb::SymAttributeSet attrs = buildSymbolicExpressionAttributes(ea, index, symbolicInfo);

    // Symbolic expression from relocation
    if(const auto symbolicExpr =
           symbolicInfo.SymbolicExpressionsFromRelocations.find(ea + instruction.immediateOffset);
       symbolicExpr != symbolicInfo.SymbolicExpressionsFromRelocations.end())
    {
        auto foundSymbol = module.findSymbols(symbolicExpr->Symbol);
        if(foundSymbol.begin() != foundSymbol.end())
        {
            // FIXME: We need to handle overlapping sections here.
            addSymbolicExpressionToCodeBlock<gtirb::SymAddrConst>(
                module, ea, symbolicExpr->Size, instruction.immediateOffset, symbolicExpr->Addend,
                &*foundSymbol.begin(), attrs);
            return;
        }
    }
    // Symbol-Symbol case
    auto rangeRelSym =
        symbolicInfo.SymbolicBaseMinusConst.equal_range(ea + instruction.immediateOffset);
    if(auto relSym = rangeRelSym.first; relSym != rangeRelSym.second)
    {
        gtirb::Symbol *sym1 = getSymbol(context, module, gtirb::Addr(relSym->Symbol1));
        gtirb::Symbol *sym2 = getSymbol(context, module, gtirb::Addr(relSym->Symbol2));

        addSymbolicExpressionToCodeBlock<gtirb::SymAddrAddr>(
            module, ea, instruction.Size - instruction.immediateOffset, instruction.immediateOffset,
            1, 0, sym1, sym2, attrs);
        return;
    }
    // Symbol+constant case
    auto rangeMovedLabel = symbolicInfo.MovedLabels.equal_range(ea);
    if(auto movedLabel =
           std::find_if(rangeMovedLabel.first, rangeMovedLabel.second,
                        [index](const auto &element) { return element.OperandIndex == index; });
       movedLabel != rangeMovedLabel.second)
    {
        assert(movedLabel->Address1 == gtirb::Addr(immediate));
        auto diff = movedLabel->Address1 - movedLabel->Address2;
        auto sym = getSymbol(context, module, gtirb::Addr(movedLabel->Address2));
        addSymbolicExpressionToCodeBlock<gtirb::SymAddrConst>(
            module, ea, instruction.Size - instruction.immediateOffset, instruction.immediateOffset,
            diff, sym, attrs);
        return;
    }
    // Symbol+0 case
    auto range = symbolicInfo.SymbolicExpressionNoOffsets.equal_range(ea);
    if(auto symOp =
           std::find_if(range.first, range.second,
                        [index](const auto &element) { return element.OperandIndex == index; });
       symOp != range.second)
    {
        auto sym = getSymbol(context, module, gtirb::Addr(symOp->Dest));
        addSymbolicExpressionToCodeBlock<gtirb::SymAddrConst>(
            module, ea, instruction.Size - instruction.immediateOffset, instruction.immediateOffset,
            0, sym, attrs);
        return;
    }
}

void buildSymbolicIndirect(gtirb::Context &context, gtirb::Module &module, const gtirb::Addr &ea,
                           const DecodedInstruction &instruction, uint64_t index,
                           const SymbolicInfo &symbolicInfo)
{
    uint64_t DispSize = 0;
    if(instruction.displacementOffset > 0)
    {
        uint64_t Size = instruction.Size;
        uint64_t Imm = instruction.immediateOffset;
        uint64_t Disp = instruction.displacementOffset;
        DispSize = Imm > Disp ? Imm - Disp : Size - Disp;
    }

    gtirb::SymAttributeSet attrs = buildSymbolicExpressionAttributes(ea, index, symbolicInfo);

    // Symbolic expression form relocation
    if(const auto symbolicExpr = symbolicInfo.SymbolicExpressionsFromRelocations.find(
           ea + instruction.displacementOffset);
       symbolicExpr != symbolicInfo.SymbolicExpressionsFromRelocations.end())
    {
        auto foundSymbol = module.findSymbols(symbolicExpr->Symbol);
        if(foundSymbol.begin() != foundSymbol.end())
        {
            addSymbolicExpressionToCodeBlock<gtirb::SymAddrConst>(
                module, ea, symbolicExpr->Size, instruction.displacementOffset,
                symbolicExpr->Addend, &*foundSymbol.begin(), attrs);
            return;
        }
    }
    // Symbol-Symbol and (Symbol-Symbol)+Offset
    auto rangeRelSym =
        symbolicInfo.SymbolicBaseMinusConst.equal_range(ea + instruction.displacementOffset);
    if(auto relSym = rangeRelSym.first; relSym != rangeRelSym.second)
    {
        int64_t offset = 0;
        gtirb::Symbol *sym1 = getSymbol(context, module, gtirb::Addr(relSym->Symbol1));
        gtirb::Symbol *sym2;

        auto rangeMovedLabel = symbolicInfo.MovedLabels.equal_range(ea);
        if(auto movedLabel =
               std::find_if(rangeMovedLabel.first, rangeMovedLabel.second,
                            [index](const auto &element) { return element.OperandIndex == index; });
           movedLabel != rangeMovedLabel.second)
        {
            // (Symbol-Symbol)+Offset
            sym2 = getSymbol(context, module, gtirb::Addr(movedLabel->Address2));
            offset = movedLabel->Address1 - movedLabel->Address2;
        }
        else
        {
            // Symbol-Symbol
            sym2 = getSymbol(context, module, gtirb::Addr(relSym->Symbol2));
        }

        addSymbolicExpressionToCodeBlock<gtirb::SymAddrAddr>(
            module, ea, DispSize, instruction.displacementOffset, 1, offset, sym2, sym1, attrs);
        return;
    }
    // Symbol+constant case
    auto rangeMovedLabel = symbolicInfo.MovedLabels.equal_range(ea);
    if(auto movedLabel =
           std::find_if(rangeMovedLabel.first, rangeMovedLabel.second,
                        [index](const auto &element) { return element.OperandIndex == index; });
       movedLabel != rangeMovedLabel.second)
    {
        auto diff = movedLabel->Address1 - movedLabel->Address2;
        auto sym = getSymbol(context, module, gtirb::Addr(movedLabel->Address2));
        addSymbolicExpressionToCodeBlock<gtirb::SymAddrConst>(
            module, ea, DispSize, instruction.displacementOffset, diff, sym, attrs);
        return;
    }
    // Symbol+0 case
    auto Range = symbolicInfo.SymbolicExpressionNoOffsets.equal_range(ea);
    if(auto SymbolicExpr =
           std::find_if(Range.first, Range.second,
                        [index](const auto &Element) { return Element.OperandIndex == index; });
       SymbolicExpr != Range.second)
    {
        auto sym = getSymbol(context, module, gtirb::Addr(SymbolicExpr->Dest));
        addSymbolicExpressionToCodeBlock<gtirb::SymAddrConst>(
            module, ea, DispSize, instruction.displacementOffset, 0, sym, attrs);
        return;
    }
}

void buildCodeSymbolicInformation(gtirb::Context &context, gtirb::Module &module,
                                  souffle::SouffleProgram *prog)
{
    auto codeInBlock = convertRelation<CodeInBlock>("code_in_refined_block", prog);
    SymbolicInfo symbolicInfo{
        convertSortedRelation<VectorByEA<MovedLabel>>("moved_label", prog),
        convertSortedRelation<VectorByEA<SymbolicExpressionNoOffset>>("symbolic_operand", prog),
        convertSortedRelation<VectorByEA<SymbolicExpr>>("symbolic_expr_from_relocation", prog),
        convertSortedRelation<VectorByEA<SymbolMinusSymbol>>("symbol_minus_symbol", prog),
        convertSortedRelation<VectorByEA<SymbolicOperandAttribute>>("symbolic_operand_attribute",
                                                                    prog)};
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
            if(std::get_if<IndirectOp>(&op.second))
                buildSymbolicIndirect(context, module, inst->first, inst->second, op.first,
                                      symbolicInfo);
        }
    }
}

void buildCodeBlocks(gtirb::Context &context, gtirb::Module &module, souffle::SouffleProgram *prog)
{
    auto blockInformation =
        convertSortedRelation<VectorByEA<BlockInformation>>("block_information", prog);
    for(auto &output : *prog->getRelation("refined_block"))
    {
        gtirb::Addr blockAddress;
        output >> blockAddress;
        if(auto sections = module.findSectionsOn(blockAddress); !sections.empty())
        {
            gtirb::Section &section = *sections.begin();
            uint64_t size = blockInformation.find(blockAddress)->size;
            if(auto it = section.findByteIntervalsOn(blockAddress); !it.empty())
            {
                if(gtirb::ByteInterval &byteInterval = *it.begin(); byteInterval.getAddress())
                {
                    uint64_t blockOffset = blockAddress - *byteInterval.getAddress();
                    byteInterval.addBlock<gtirb::CodeBlock>(context, blockOffset, size);
                }
            }
        }
    }
}

// Create DataObjects for labeled objects in the BSS sections, without adding
// data to the ImageByteMap.

void buildBSS(gtirb::Context &context, gtirb::Module &module, souffle::SouffleProgram *prog)
{
    auto bssData = convertSortedRelation<std::set<gtirb::Addr>>("bss_data", prog);
    for(auto &output : *prog->getRelation("bss_section"))
    {
        std::string sectionName;
        output >> sectionName;
        const auto bss_section = module.findSections(sectionName);
        if(bss_section == module.sections_by_name_end())
            continue;
        // for each bss section we divide in data objects according to the bss_data markers that
        // fall within the range of the section
        auto beginning = bssData.lower_bound(bss_section->getAddress().value());
        // end points to the address at the end of the bss section
        auto end = bssData.lower_bound(*addressLimit(*bss_section));
        for(auto i = beginning; i != end; ++i)
        {
            auto next = i;
            next++;
            if(auto it = module.findByteIntervalsOn(*i); !it.empty())
            {
                gtirb::ByteInterval &byteInterval = *it.begin();
                uint64_t blockOffset = *i - byteInterval.getAddress().value();
                byteInterval.addBlock<gtirb::DataBlock>(context, blockOffset,
                                                        static_cast<uint64_t>(*next - *i));
            }
        }
    }
}

void buildDataBlocks(gtirb::Context &context, gtirb::Module &module, souffle::SouffleProgram *prog)
{
    auto symbolicData = convertSortedRelation<VectorByEA<SymbolicData>>("symbolic_data", prog);
    auto movedDataLabels =
        convertSortedRelation<VectorByEA<MovedDataLabel>>("moved_data_label", prog);
    auto symbolicExprs =
        convertSortedRelation<VectorByEA<SymbolicExpr>>("symbolic_expr_from_relocation", prog);
    auto symbolMinusSymbol =
        convertSortedRelation<VectorByEA<SymbolMinusSymbol>>("symbol_minus_symbol", prog);

    auto dataStrings = convertSortedRelation<VectorByEA<StringDataObject>>("string", prog);
    auto symbolSpecialTypes =
        convertSortedRelation<VectorByEA<SymbolSpecialType>>("symbol_special_encoding", prog);
    auto DataBoundary = convertSortedRelation<std::set<gtirb::Addr>>("data_object_boundary", prog);
    std::map<gtirb::UUID, std::string> typesTable;

    std::map<gtirb::Offset, uint64_t> SymbolicSizes;

    for(auto &output : *prog->getRelation("initialized_data_segment"))
    {
        gtirb::Addr begin, end;
        output >> begin >> end;
        // we don't create data blocks that exceed the data segment
        DataBoundary.insert(end);
        for(auto currentAddr = begin; currentAddr < end;
            /*incremented in each case*/)
        {
            gtirb::DataBlock *d;
            if(auto it = module.findByteIntervalsOn(currentAddr); !it.empty())
            {
                if(gtirb::ByteInterval &byteInterval = *it.begin(); byteInterval.getAddress())
                {
                    // do not cross byte intervals.
                    DataBoundary.insert(*byteInterval.getAddress() + byteInterval.getSize());
                    uint64_t blockOffset = currentAddr - *byteInterval.getAddress();
                    gtirb::Offset Offset = gtirb::Offset(byteInterval.getUUID(), blockOffset);

                    // symbolic expression created from relocation
                    if(const auto symbolicExpr = symbolicExprs.find(currentAddr);
                       symbolicExpr != symbolicExprs.end())
                    {
                        d = gtirb::DataBlock::Create(context, symbolicExpr->Size);
                        auto foundSymbol = module.findSymbols(symbolicExpr->Symbol);
                        if(foundSymbol.begin() != foundSymbol.end())
                            byteInterval.addSymbolicExpression<gtirb::SymAddrConst>(
                                blockOffset, symbolicExpr->Addend, &*foundSymbol.begin());
                        SymbolicSizes[Offset] = symbolicExpr->Size;
                    }
                    else
                        // symbol+constant
                        if(const auto movedDataLabel = movedDataLabels.find(currentAddr);
                           movedDataLabel != movedDataLabels.end())
                    {
                        d = gtirb::DataBlock::Create(context, movedDataLabel->Size);
                        auto diff = movedDataLabel->Address1 - movedDataLabel->Address2;
                        auto sym =
                            getSymbol(context, module, gtirb::Addr(movedDataLabel->Address2));
                        byteInterval.addSymbolicExpression<gtirb::SymAddrConst>(blockOffset, diff,
                                                                                sym);
                        SymbolicSizes[Offset] = movedDataLabel->Size;
                    }
                    else
                        // symbol+0
                        if(const auto symbolic = symbolicData.find(currentAddr);
                           symbolic != symbolicData.end())
                    {
                        d = gtirb::DataBlock::Create(context, symbolic->Size);
                        auto sym = getSymbol(context, module, symbolic->GroupContent);
                        byteInterval.addSymbolicExpression<gtirb::SymAddrConst>(blockOffset, 0,
                                                                                sym);
                        SymbolicSizes[Offset] = symbolic->Size;
                    }
                    else
                        // symbol-symbol
                        if(const auto symMinusSym = symbolMinusSymbol.find(currentAddr);
                           symMinusSym != symbolMinusSymbol.end())
                    {
                        d = gtirb::DataBlock::Create(context, symMinusSym->Size);
                        byteInterval.addSymbolicExpression<gtirb::SymAddrAddr>(
                            blockOffset, static_cast<int64_t>(symMinusSym->Scale), 0,
                            getSymbol(context, module, symMinusSym->Symbol2),
                            getSymbol(context, module, symMinusSym->Symbol1));
                        SymbolicSizes[Offset] = symMinusSym->Size;
                    }
                    else
                        // string
                        if(const auto str = dataStrings.find(currentAddr); str != dataStrings.end())
                    {
                        d = gtirb::DataBlock::Create(context, str->End - currentAddr);
                        typesTable[d->getUUID()] = std::string{"string"};
                    }
                    else
                    {
                        // Accumulate region with no symbols into a single DataBlock.
                        auto NextDataObject = DataBoundary.lower_bound(currentAddr + 1);
                        d = gtirb::DataBlock::Create(context, *NextDataObject - currentAddr);
                    }
                    // symbol special types
                    const auto specialType = symbolSpecialTypes.find(currentAddr);
                    if(specialType != symbolSpecialTypes.end())
                        typesTable[d->getUUID()] = specialType->Type;
                    byteInterval.addBlock(blockOffset, d);
                    currentAddr += d->getSize();
                }
            }
        }
    }
    buildBSS(context, module, prog);
    module.addAuxData<gtirb::schema::Encodings>(std::move(typesTable));
    module.addAuxData<gtirb::schema::SymbolicExpressionSizes>(std::move(SymbolicSizes));
}

gtirb::Section *findSectionByIndex(gtirb::Context &C, gtirb::Module &M, uint64_t Index)
{
    auto *SectionIndex = M.getAuxData<gtirb::schema::ElfSectionIndex>();
    if(auto It = SectionIndex->find(Index); It != SectionIndex->end())
    {
        gtirb::Node *N = gtirb::Node::getByUUID(C, It->second);
        if(auto *Section = dyn_cast_or_null<gtirb::Section>(N))
        {
            return Section;
        }
    }
    return nullptr;
};

void connectSymbolsToBlocks(gtirb::Context &Context, gtirb::Module &Module)
{
    auto *SymbolInfo = Module.getAuxData<gtirb::schema::ElfSymbolInfoAD>();

    std::map<gtirb::Symbol *, std::tuple<gtirb::Node *, bool>> ConnectToBlock;
    for(auto &Symbol : Module.symbols_by_addr())
    {
        if(Symbol.getAddress())
        {
            gtirb::Addr Addr = *Symbol.getAddress();
            if(auto It = Module.findCodeBlocksAt(Addr); !It.empty())
            {
                gtirb::CodeBlock &Block = It.front();
                assert(Addr == *Block.getAddress());
                ConnectToBlock[&Symbol] = {&Block, false};
                continue;
            }
            if(auto It = Module.findDataBlocksAt(Addr); !It.empty())
            {
                gtirb::DataBlock &Block = It.front();
                assert(Addr == *Block.getAddress());
                ConnectToBlock[&Symbol] = {&Block, false};
                continue;
            }
            if(auto It = Module.findCodeBlocksOn(Addr); !It.empty())
            {
                gtirb::CodeBlock &Block = It.front();
                if(Addr > *Block.getAddress())
                {
                    std::cerr << "WARNING: Found integral symbol pointing into existing block:"
                              << Symbol.getName() << std::endl;
                    continue;
                }
            }
            if(auto It = Module.findDataBlocksOn(Addr); !It.empty())
            {
                gtirb::DataBlock &Block = It.front();
                if(Addr > *Block.getAddress())
                {
                    std::cerr << "WARNING: Found integral symbol pointing into existing block: "
                              << Symbol.getName() << std::endl;
                    continue;
                }
            }
            if(auto It = Module.findSectionsOn(Addr - 1); !It.empty())
            {
                if(gtirb::Section &Section = It.front(); Section.getAddress() && Section.getSize())
                {
                    // Symbol points to byte immediately following section.
                    if(Addr == (*Section.getAddress() + *Section.getSize()))
                    {
                        if(auto BlockIt = Section.findBlocksOn(Addr - 1); !BlockIt.empty())
                        {
                            gtirb::Node &Block = BlockIt.front();
                            ConnectToBlock[&Symbol] = {&Block, true};
                            continue;
                        }
                    }
                }
            }
            if(SymbolInfo && SymbolInfo->count(Symbol.getUUID()) > 0)
            {
                ElfSymbolInfo Info = (*SymbolInfo)[Symbol.getUUID()];
                uint64_t SectionIndex = std::get<4>(Info);
                if(gtirb::Section *Section = findSectionByIndex(Context, Module, SectionIndex);
                   Section && Section->getAddress() && Section->getSize())
                {
                    if(Addr < Section->getAddress())
                    {
                        if(auto It = Section->blocks(); !It.empty())
                        {
                            std::cerr << "WARNING: Moving symbol to first block of section: "
                                      << Symbol.getName() << std::endl;
                            ConnectToBlock[&Symbol] = {&*It.begin(), false};
                            continue;
                        }
                    }
                }
            }
        }
    }

    for(auto [Symbol, T] : ConnectToBlock)
    {
        auto [Node, AtEnd] = T;
        if(gtirb::CodeBlock *CodeBlock = dyn_cast_or_null<gtirb::CodeBlock>(Node))
        {
            Symbol->setReferent(CodeBlock);
            Symbol->setAtEnd(AtEnd);
        }
        else if(gtirb::DataBlock *DataBlock = dyn_cast_or_null<gtirb::DataBlock>(Node))
        {
            Symbol->setReferent(DataBlock);
            Symbol->setAtEnd(AtEnd);
        }
    }

    Module.removeAuxData<gtirb::schema::ElfSectionIndex>();
}

void splitSymbols(gtirb::Context &Context, gtirb::Module &Module, souffle::SouffleProgram *Program)
{
    for(auto &T : *Program->getRelation("boundary_label"))
    {
        gtirb::Addr EA, Start, End;
        T >> EA >> Start >> End;

        if(auto It = Module.findDataBlocksOn(EA); !It.empty())
        {
            gtirb::DataBlock &Block = It.front();
            if(gtirb::ByteInterval *BI = Block.getByteInterval(); BI && BI->getAddress())
            {
                uint64_t Offset = EA - *(BI->getAddress());
                if(gtirb::SymbolicExpression *Expr = BI->getSymbolicExpression(Offset))
                {
                    if(auto *SAA = std::get_if<gtirb::SymAddrAddr>(Expr))
                    {
                        gtirb::Symbol *S = SAA->Sym1;
                        if(S && !S->getAtEnd() && S->getAddress() == End)
                        {
                            std::stringstream Stream;
                            Stream << "__end_" << std::hex << static_cast<uint64_t>(Start);
                            std::string Label = Stream.str();

                            gtirb::Symbol *NewSymbol = Module.addSymbol(Context, End, Label);
                            if(auto BlockIt = Module.findCodeBlocksOn(Start); !BlockIt.empty())
                            {
                                gtirb::CodeBlock &CodeBlock = BlockIt.front();
                                NewSymbol->setReferent(&CodeBlock);
                            }
                            NewSymbol->setAtEnd(true);
                            SAA->Sym1 = NewSymbol;
                        }
                    }
                }
            }
        }
    }
}

void buildFunctions(gtirb::Module &module, souffle::SouffleProgram *prog)
{
    std::map<gtirb::UUID, std::set<gtirb::UUID>> functionEntries;
    std::map<gtirb::Addr, gtirb::UUID> functionEntry2function;
    std::map<gtirb::UUID, gtirb::UUID> functionNames;
    boost::uuids::random_generator generator;
    for(auto &output : *prog->getRelation("function_inference.function_entry"))
    {
        gtirb::Addr functionEntry;
        output >> functionEntry;
        auto blockRange = module.findCodeBlocksAt(functionEntry);
        if(!blockRange.empty())
        {
            const gtirb::UUID &entryBlockUUID = blockRange.begin()->getUUID();
            gtirb::UUID functionUUID = generator();

            functionEntry2function[functionEntry] = functionUUID;
            functionEntries[functionUUID].insert(entryBlockUUID);

            for(const auto &symbol : module.findSymbols(functionEntry))
            {
                functionNames.insert({functionUUID, symbol.getUUID()});
            }
        }
    }

    std::map<gtirb::UUID, std::set<gtirb::UUID>> functionBlocks;
    for(auto &output : *prog->getRelation("function_inference.in_function"))
    {
        gtirb::Addr blockAddr, functionEntryAddr;
        output >> blockAddr >> functionEntryAddr;
        auto blockRange = module.findCodeBlocksOn(blockAddr);
        if(!blockRange.empty())
        {
            gtirb::CodeBlock *block = &*blockRange.begin();
            gtirb::UUID functionEntryUUID = functionEntry2function[functionEntryAddr];
            functionBlocks[functionEntryUUID].insert(block->getUUID());
        }
    }

    module.addAuxData<gtirb::schema::FunctionEntries>(std::move(functionEntries));
    module.addAuxData<gtirb::schema::FunctionBlocks>(std::move(functionBlocks));
    module.addAuxData<gtirb::schema::FunctionNames>(std::move(functionNames));
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
    auto &cfg = module.getIR()->getCFG();
    for(auto &output : *prog->getRelation("cfg_edge"))
    {
        gtirb::Addr srcAddr, destAddr;
        std::string conditional, indirect, type;
        output >> srcAddr >> destAddr >> conditional >> indirect >> type;

        // ddisasm guarantees that these blocks exist
        const gtirb::CodeBlock *src = &*module.findCodeBlocksOn(srcAddr).begin();
        const gtirb::CodeBlock *dest = &*module.findCodeBlocksOn(destAddr).begin();

        auto isConditional = conditional == "true" ? gtirb::ConditionalEdge::OnTrue
                                                   : gtirb::ConditionalEdge::OnFalse;
        auto isIndirect =
            indirect == "true" ? gtirb::DirectEdge::IsIndirect : gtirb::DirectEdge::IsDirect;
        gtirb::EdgeType edgeType = getEdgeType(type);

        auto E = addEdge(src, dest, cfg);
        cfg[*E] = std::make_tuple(isConditional, isIndirect, edgeType);
    }
    auto *topBlock = module.addProxyBlock(context);
    for(auto &output : *prog->getRelation("cfg_edge_to_top"))
    {
        gtirb::Addr srcAddr;
        std::string conditional, type;
        output >> srcAddr >> conditional >> type;
        const gtirb::CodeBlock *src = &*module.findCodeBlocksOn(srcAddr).begin();
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
        const gtirb::CodeBlock *src = &*module.findCodeBlocksOn(srcAddr).begin();
        gtirb::Symbol &symbol = *module.findSymbols(symbolName).begin();
        gtirb::ProxyBlock *externalBlock = symbol.getReferent<gtirb::ProxyBlock>();
        // if the symbol does not point to a ProxyBlock yet, we create it
        if(!externalBlock)
        {
            externalBlock = module.addProxyBlock(context);
            symbol.setReferent(externalBlock);
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
    for(auto &block : module.findCodeBlocksOn(ea))
    {
        offsets.push_back(gtirb::Offset(block.getUUID(), ea - block.getAddress().value()));
    }
    for(auto &dataObject : module.findDataBlocksOn(ea))
    {
        offsets.push_back(
            gtirb::Offset(dataObject.getUUID(), ea - dataObject.getAddress().value()));
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
        uint64_t disp, localIndex, nOperands;
        int64_t op1, op2;
        output >> blockAddr >> disp >> localIndex >> directive >> reference >> nOperands >> op1
            >> op2;
        std::vector<int64_t> operands;
        // cfi_escape directives have a sequence of bytes as operands (the raw bytes of the
        // dwarf instruction). The address 'reference' points to these bytes.
        if(directive == ".cfi_escape")
        {
            if(const auto it = module.findByteIntervalsOn(reference); !it.empty())
            {
                if(const gtirb::ByteInterval &interval = *it.begin(); interval.getAddress())
                {
                    auto begin =
                        interval.bytes_begin<uint8_t>() + (reference - *interval.getAddress());
                    auto end = begin + nOperands;
                    for(uint8_t byte : boost::make_iterator_range(begin, end))
                    {
                        operands.push_back(static_cast<int64_t>(byte));
                    }
                }
            }
        }
        else
        {
            if(nOperands > 0)
                operands.push_back(op1);
            if(nOperands > 1)
                operands.push_back(op2);
        }

        auto blockRange = module.findCodeBlocksOn(blockAddr);
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
    module.addAuxData<gtirb::schema::CfiDirectives>(std::move(cfiDirectives));
}

void buildPadding(gtirb::Module &Module, souffle::SouffleProgram *Prog)
{
    std::map<gtirb::Offset, uint64_t> Padding;
    for(auto &Output : *Prog->getRelation("padding"))
    {
        gtirb::Addr EA;
        uint64_t Size;
        Output >> EA >> Size;
        if(auto It = Module.findByteIntervalsOn(EA); !It.empty())
        {
            if(gtirb::ByteInterval &ByteInterval = *It.begin(); ByteInterval.getAddress())
            {
                uint64_t BlockOffset = EA - *ByteInterval.getAddress();
                gtirb::Offset Offset = gtirb::Offset(ByteInterval.getUUID(), BlockOffset);
                Padding[Offset] = Size;
            }
        }
    }
    Module.addAuxData<gtirb::schema::Padding>(std::move(Padding));
}

void buildComments(gtirb::Module &module, souffle::SouffleProgram *prog, bool selfDiagnose)
{
    std::map<gtirb::Offset, std::string> comments;
    for(auto &output : *prog->getRelation("data_access_pattern"))
    {
        gtirb::Addr ea;
        uint64_t size, from;
        int64_t multiplier;
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
        gtirb::Addr ea, ea2;
        std::string reg, reg2;
        int64_t multiplier, offset;
        output >> ea >> reg >> ea2 >> reg2 >> multiplier >> offset;
        std::ostringstream newComment;
        newComment << reg << "=(" << reg2 << "," << std::hex << ea2 << std::dec << ")*"
                   << multiplier << "+" << std::hex << offset << std::dec;
        updateComment(module, comments, ea, newComment.str());
    }

    for(auto &output : *prog->getRelation("moved_label_class"))
    {
        gtirb::Addr ea;
        uint64_t opIndex;
        std::string type;

        output >> ea >> opIndex >> type;
        std::ostringstream newComment;
        newComment << " moved label-" << type;
        updateComment(module, comments, ea, newComment.str());
    }

    for(auto &output : *prog->getRelation("def_used"))
    {
        gtirb::Addr ea_use, ea_def;
        uint64_t index;
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
            uint64_t index;
            output >> ea >> index;
            std::ostringstream newComment;
            newComment << "bad_symbol_constant(" << index << ")";
            updateComment(module, comments, ea, newComment.str());
        }
    }
    module.addAuxData<gtirb::schema::Comments>(std::move(comments));
}

void updateEntryPoint(gtirb::Module &module, souffle::SouffleProgram *prog)
{
    for(auto &output : *prog->getRelation("entry_point"))
    {
        gtirb::Addr ea;
        output >> ea;

        if(const auto it = module.findCodeBlocksAt(ea); !it.empty())
        {
            module.setEntryPoint(&*it.begin());
        }
    }
    assert(module.getEntryPoint() && "Failed to set module entry point.");
}

void disassembleModule(gtirb::Context &context, gtirb::Module &module,
                       souffle::SouffleProgram *prog, bool selfDiagnose)
{
    buildInferredSymbols(context, module, prog);
    buildSymbolForwarding(context, module, prog);
    buildCodeBlocks(context, module, prog);
    buildDataBlocks(context, module, prog);
    buildCodeSymbolicInformation(context, module, prog);
    buildCfiDirectives(context, module, prog);
    expandSymbolForwarding(context, module, prog);
    // This should be done after creating all the symbols.
    connectSymbolsToBlocks(context, module);
    splitSymbols(context, module, prog);
    // These functions should not create additional symbols.
    buildFunctions(module, prog);
    buildCFG(context, module, prog);
    buildPadding(module, prog);
    buildComments(module, prog, selfDiagnose);
    updateEntryPoint(module, prog);
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
