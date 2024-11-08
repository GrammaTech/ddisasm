//===- Disassembler.cpp -----------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2019-2023 GrammaTech, Inc.
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
#include <regex>

#include "../AuxDataSchema.h"
#include "../gtirb-decoder/Relations.h"

using ImmOp = int64_t;
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
    std::map<uint64_t, std::variant<ImmOp, IndirectOp>> Operands;
    uint64_t immediateOffset;
    uint64_t displacementOffset;
};

std::map<gtirb::Addr, DecodedInstruction> recoverInstructions(souffle::SouffleProgram &Program,
                                                              std::set<gtirb::Addr> &Code)
{
    std::map<uint64_t, ImmOp> Immediates;
    for(auto &Output : *Program.getRelation("op_immediate"))
    {
        uint64_t OperandCode, Size;
        ImmOp Immediate;
        Output >> OperandCode >> Immediate >> Size;
        Immediates[OperandCode] = Immediate;
    };
    std::map<uint64_t, IndirectOp> Indirects;
    for(auto &Output : *Program.getRelation("op_indirect"))
    {
        uint64_t OperandCode, Size;
        IndirectOp Indirect;
        Output >> OperandCode >> Indirect.Reg1 >> Indirect.Reg2 >> Indirect.Reg3 >> Indirect.Mult
            >> Indirect.Disp >> Size;
        Indirects[OperandCode] = Indirect;
    };

    std::map<gtirb::Addr, DecodedInstruction> Insns;
    for(auto &Output : *Program.getRelation("instruction"))
    {
        gtirb::Addr EA;
        Output >> EA;

        // Don't bother recovering instructions that aren't considered code.
        if(Code.count(EA) == 0)
        {
            continue;
        }

        DecodedInstruction Insn;
        uint64_t Size;
        std::string Prefix, Opcode;
        Output >> Size >> Prefix >> Opcode;

        for(size_t i = 1; i <= 4; i++)
        {
            uint64_t OperandIndex;
            Output >> OperandIndex;
            auto FoundImmediate = Immediates.find(OperandIndex);
            if(FoundImmediate != Immediates.end())
                Insn.Operands[i] = FoundImmediate->second;
            else
            {
                auto FoundIndirect = Indirects.find(OperandIndex);
                if(FoundIndirect != Indirects.end())
                    Insn.Operands[i] = FoundIndirect->second;
            }
        }
        Output >> Insn.immediateOffset >> Insn.displacementOffset;
        Insns[EA] = Insn;
    }
    return Insns;
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
        assert(tuple.size() == 4);
        tuple >> EA >> size;
    };

    gtirb::Addr EA{0};
    uint64_t size{0};
};

template <typename T>
using VectorByEA = boost::multi_index_container<
    T, boost::multi_index::indexed_by<boost::multi_index::ordered_non_unique<
           boost::multi_index::member<T, decltype(T::EA), &T::EA>>>>;

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

struct SymExprSymbolMinusSymbol
{
    SymExprSymbolMinusSymbol(gtirb::Addr ea) : EA(ea)
    {
    }

    SymExprSymbolMinusSymbol(souffle::tuple &tuple)
    {
        assert(tuple.size() == 6);

        tuple >> EA >> Size >> Symbol1 >> Symbol2 >> Scale >> Offset;
    };

    gtirb::Addr EA{0};
    uint64_t Size;
    std::string Symbol1;
    std::string Symbol2;
    uint64_t Scale;
    int64_t Offset;
};

struct SymbolicExprAttribute
{
    explicit SymbolicExprAttribute(gtirb::Addr A) : EA(A)
    {
    }
    explicit SymbolicExprAttribute(souffle::tuple &T)
    {
        assert(T.size() == 2);
        T >> EA >> Type;
    }
    gtirb::Addr EA{0};
    std::string Type{"NONE"};
};

struct StringDataObject
{
    StringDataObject(gtirb::Addr A) : EA(A)
    {
    }

    StringDataObject(souffle::tuple &T)
    {
        assert(T.size() == 3);
        T >> EA >> End >> Encoding;
    };

    gtirb::Addr EA{0};
    gtirb::Addr End{0};
    std::string Encoding{"NONE"};
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

struct Alignment
{
    explicit Alignment(gtirb::Addr A) : EA(A)
    {
    }
    explicit Alignment(souffle::tuple &T)
    {
        assert(T.size() == 2);
        T >> EA >> Num;
    }
    gtirb::Addr EA{0};
    uint64_t Num{0};
};

struct SymbolicInfo
{
    VectorByEA<SymbolicExpr> SymbolicExprs;
    VectorByEA<SymExprSymbolMinusSymbol> SymbolMinusSymbolSymbolicExprs;
    VectorByEA<SymbolicExprAttribute> SymbolicExprAttributes;
};

template <typename Container, typename Elem = typename Container::value_type>
Container convertSortedRelation(const std::string &relation, souffle::SouffleProgram &Program)
{
    Container result;
    for(auto &output : *Program.getRelation(relation))
    {
        Elem elem(output);
        result.insert(elem);
    }
    return result;
}

template <>
std::set<gtirb::Addr> convertSortedRelation<std::set<gtirb::Addr>>(const std::string &relation,
                                                                   souffle::SouffleProgram &Program)
{
    std::set<gtirb::Addr> result;
    for(auto &output : *Program.getRelation(relation))
    {
        result.insert(gtirb::Addr(output[0]));
    };
    return result;
}

std::string stripSymbolVersion(const std::string Name)
{
    if(size_t I = Name.find('@'); I != std::string::npos)
    {
        return Name.substr(0, I);
    }
    return Name;
}

void removeEntryPoint(gtirb::Module &Module)
{
    // Remove initial entry point.
    // ElfReader and PeReader create a code block with zero size to set the entrypoint.
    // It's no longer needed; we connect it to a real code block once it's created.
    if(gtirb::CodeBlock *Block = Module.getEntryPoint())
    {
        Block->getByteInterval()->removeBlock(Block);
    }
    Module.setEntryPoint(nullptr);
}

void removeSectionSymbols(gtirb::Context &Context, gtirb::Module &Module)
{
    auto *SymbolInfo = Module.getAuxData<gtirb::schema::ElfSymbolInfo>();
    auto *SymbolTabIdxInfo = Module.getAuxData<gtirb::schema::ElfSymbolTabIdxInfo>();
    if(!SymbolInfo)
    {
        return;
    }
    std::vector<gtirb::UUID> Remove;
    for(const auto &[Uuid, Info] : *SymbolInfo)
    {
        if(std::get<1>(Info) == "SECTION")
        {
            Remove.push_back(Uuid);
        }
    }
    for(const auto Uuid : Remove)
    {
        gtirb::Node *N = gtirb::Node::getByUUID(Context, Uuid);
        if(auto *Symbol = gtirb::dyn_cast_or_null<gtirb::Symbol>(N))
        {
            Module.removeSymbol(Symbol);
            SymbolInfo->erase(Uuid);
        }

        // Remove auxdata that refer to the symbol.
        if(SymbolTabIdxInfo)
        {
            SymbolTabIdxInfo->erase(Uuid);
        }
    }
}

void removeSymbolVersionsFromNames(gtirb::Module &Module)
{
    if(Module.getFileFormat() != gtirb::FileFormat::ELF)
    {
        return;
    }
    std::vector<std::tuple<gtirb::Symbol *, std::string>> Versioned;
    for(auto &Symbol : Module.symbols())
    {
        const std::string &Name = Symbol.getName();
        if(size_t I = Name.find('@'); I != std::string::npos)
        {
            Versioned.push_back({&Symbol, Name.substr(0, I)});
        }
    }
    for(auto [Symbol, Name] : Versioned)
    {
        Symbol->setName(Name);
    }
}

void buildInferredSymbols(gtirb::Context &Context, gtirb::Module &Module,
                          souffle::SouffleProgram &Program)
{
    auto *SymbolInfo = Module.getAuxData<gtirb::schema::ElfSymbolInfo>();
    auto *SymbolTabIdxInfo = Module.getAuxData<gtirb::schema::ElfSymbolTabIdxInfo>();
    for(auto &T : *Program.getRelation("inferred_symbol"))
    {
        gtirb::Addr Addr;
        std::string Name;
        std::string Scope, Visibility, Type;
        T >> Addr >> Name >> Scope >> Visibility >> Type;
        if(!Module.findSymbols(Name))
        {
            gtirb::Symbol *Symbol = Module.addSymbol(Context, Addr, Name);
            if(SymbolInfo)
            {
                auxdata::ElfSymbolInfo Info = {0, Type, Scope, Visibility, 0};
                SymbolInfo->insert({Symbol->getUUID(), Info});
            }
            if(SymbolTabIdxInfo)
            {
                auxdata::ElfSymbolTabIdxInfo TabIdx =
                    std::vector<std::tuple<std::string, uint64_t>>();
                SymbolTabIdxInfo->insert({Symbol->getUUID(), TabIdx});
            }
        }
    }
    // Rename ARM mapping symbols.
    std::vector<gtirb::Symbol *> MappingSymbols;
    for(auto &Symbol : Module.symbols())
    {
        std::string Name = Symbol.getName();
        if(Name == "$a" || Name == "$d" || Name.substr(0, 2) == "$t" || Name == "$x")
        {
            MappingSymbols.push_back(&Symbol);
        }
    }
    for(auto *Symbol : MappingSymbols)
    {
        Module.removeSymbol(Symbol);
        SymbolInfo->erase(Symbol->getUUID());

        // Remove auxdata that refer to the symbol.
        if(SymbolTabIdxInfo)
        {
            SymbolTabIdxInfo->erase(Symbol->getUUID());
        }
    }
}

// Auxiliary function to get a symbol with an address and name.
gtirb::Symbol *findSymbol(gtirb::Module &module, gtirb::Addr Ea, std::string Name)
{
    auto Found = module.findSymbols(Ea);
    for(gtirb::Symbol &Symbol : Found)
    {
        if(Symbol.getName() == Name)
            return &Symbol;
    }
    return nullptr;
}

// Auxiliary function to get the first symbol with a given name.
// The function will exit with an error if no such symbol exists.
gtirb::Symbol *findFirstSymbol(gtirb::Module &Module, std::string Name)
{
    auto Found = Module.findSymbols(Name);
    if(Found.begin() == Found.end())
    {
        std::cerr << "Missing symbol: " << Name << std::endl;
        exit(1);
    }
    return &*Found.begin();
}

// Build a first version of the SymbolForwarding table with copy relocations and
// other ABI-specific artifacts that may be duplicated or reintroduced during
// reassembly.
void buildSymbolForwarding(gtirb::Context &Context, gtirb::Module &Module,
                           souffle::SouffleProgram &Program)
{
    std::map<gtirb::UUID, gtirb::UUID> SymbolForwarding;

    auto *SymbolInfo = Module.getAuxData<gtirb::schema::ElfSymbolInfo>();
    auto *SymbolVersions = Module.getAuxData<gtirb::provisional_schema::ElfSymbolVersions>();
    gtirb::provisional_schema::ElfSymbolVersionsEntries &SymVerEntries =
        std::get<2>(*SymbolVersions);

    for(auto &T : *Program.getRelation("copy_relocated_symbol"))
    {
        gtirb::Addr EA;
        std::string Name;
        T >> EA >> Name;

        gtirb::Symbol *CopySymbol = findSymbol(Module, EA, Name);
        if(CopySymbol)
        {
            gtirb::Symbol *RealSymbol = Module.addSymbol(Context, Name);
            RealSymbol->setReferent(Module.addProxyBlock(Context));
            Name = stripSymbolVersion(Name);
            CopySymbol->setName(Name + "_copy");
            SymbolForwarding[CopySymbol->getUUID()] = RealSymbol->getUUID();

            auto CopySymbolInfoIt = SymbolInfo->find(CopySymbol->getUUID());
            if(CopySymbolInfoIt != SymbolInfo->end())
            {
                SymbolInfo->insert({RealSymbol->getUUID(), CopySymbolInfoIt->second});
            }

            // If the copy symbol is versioned, move the version to the real
            // symbol.
            auto MapNode = SymVerEntries.extract(CopySymbol->getUUID());
            if(!MapNode.empty())
            {
                MapNode.key() = RealSymbol->getUUID();
                SymVerEntries.insert(std::move(MapNode));
            }
        }
    }

    for(auto &T : *Program.getRelation("abi_intrinsic"))
    {
        gtirb::Addr EA;
        std::string Name;
        T >> EA >> Name;

        gtirb::Symbol *Symbol = findSymbol(Module, EA, Name);
        if(Symbol)
        {
            gtirb::Symbol *NewSymbol = Module.addSymbol(Context, Name);
            // Create orphaned symbol for OBJECT copy relocation aliases.
            Name = stripSymbolVersion(Name);
            Symbol->setName(Name + "_copy");
            SymbolForwarding[Symbol->getUUID()] = NewSymbol->getUUID();
        }
    }
    Module.addAuxData<gtirb::schema::SymbolForwarding>(std::move(SymbolForwarding));
}

gtirb::SymAttributeSet buildSymbolicExpressionAttributes(
    gtirb::Addr EA, const VectorByEA<SymbolicExprAttribute> &SymbolicDataAttributes)
{
    const static std::map<std::string, gtirb::SymAttribute> AttributeMap = {
        // ELF (common)
        {"GOT", gtirb::SymAttribute::GOT},
        {"GOTPC", gtirb::SymAttribute::GOTPC},
        {"GOTOFF", gtirb::SymAttribute::GOTOFF},
        {"PCREL", gtirb::SymAttribute::PCREL},
        {"PLT", gtirb::SymAttribute::PLT},
        {"TPOFF", gtirb::SymAttribute::TPOFF},
        {"DTPOFF", gtirb::SymAttribute::DTPOFF},
        {"NTPOFF", gtirb::SymAttribute::NTPOFF},
        {"PAGE", gtirb::SymAttribute::PAGE},
        {"TLSGD", gtirb::SymAttribute::TLSGD},
        {"TLSLD", gtirb::SymAttribute::TLSLD},
        {"TLSLDM", gtirb::SymAttribute::TLSLDM},
        {"TLSDESC", gtirb::SymAttribute::TLSDESC},
        {"TLSCALL", gtirb::SymAttribute::TLSCALL},
        // ARM
        {"G0", gtirb::SymAttribute::G0},
        {"G1", gtirb::SymAttribute::G1},
        {"LO12", gtirb::SymAttribute::LO12},
        // MIPS
        {"HI", gtirb::SymAttribute::HI},
        {"LO", gtirb::SymAttribute::LO},
        {"OFST", gtirb::SymAttribute::OFST},
        // X86
        {"INDNTPOFF", gtirb::SymAttribute::INDNTPOFF},
    };
    gtirb::SymAttributeSet Attributes;

    auto Range = SymbolicDataAttributes.equal_range(EA);
    for(auto It = Range.first; It != Range.second; It++)
    {
        Attributes.insert(AttributeMap.at(It->Type));
    }

    return Attributes;
}

bool isNullReg(const std::string &reg)
{
    return reg == "NONE";
}

// Expand the SymbolForwarding table with plt references
void expandSymbolForwarding(gtirb::Module &Module, souffle::SouffleProgram &Program)
{
    auto *SymbolForwarding = Module.getAuxData<gtirb::schema::SymbolForwarding>();
    for(auto &Output : *Program.getRelation("plt_block"))
    {
        gtirb::Addr Ea;
        std::string Name;
        Output >> Ea >> Name;
        // the inference of plt_block guarantees that there is at most one
        // destination symbol for each source
        auto FoundSrc = Module.findSymbols(Ea);
        auto FoundDest = Module.findSymbols(Name);
        for(gtirb::Symbol &Src : FoundSrc)
        {
            for(gtirb::Symbol &Dest : FoundDest)
            {
                (*SymbolForwarding)[Src.getUUID()] = Dest.getUUID();
            }
        }
    }
    for(auto &Output : *Program.getRelation("got_reference"))
    {
        gtirb::Addr Ea;
        std::string Name;
        Output >> Ea >> Name;
        auto FoundSrc = Module.findSymbols(Ea);
        gtirb::Symbol *Dest = findFirstSymbol(Module, Name);
        for(gtirb::Symbol &Src : FoundSrc)
        {
            (*SymbolForwarding)[Src.getUUID()] = Dest->getUUID();
        }
    }
}

template <class ExprType, typename... Args>
void addSymbolicExpressionToCodeBlock(gtirb::Module &Module, gtirb::Addr Addr, uint64_t Size,
                                      Args... A)
{
    if(auto it = Module.findCodeBlocksOn(Addr); !it.empty())
    {
        gtirb::CodeBlock &Block = *it.begin();
        gtirb::ByteInterval *ByteInterval = Block.getByteInterval();
        std::optional<gtirb::Addr> BaseAddr = ByteInterval->getAddress();
        assert(BaseAddr && "Found byte interval without address.");
        // In ARM we substract one for symexprs in thumb mode.
        if(Module.getISA() == gtirb::ISA::ARM)
        {
            Addr -= static_cast<uint64_t>(Addr) & 1;
        }
        uint64_t BlockOffset = static_cast<uint64_t>(Addr - *BaseAddr);
        ByteInterval->addSymbolicExpression<ExprType>(BlockOffset, A...);
        if(auto *Sizes = Module.getAuxData<gtirb::schema::SymbolicExpressionSizes>())
        {
            gtirb::Offset ExpressionOffset = gtirb::Offset(ByteInterval->getUUID(), BlockOffset);
            (*Sizes)[ExpressionOffset] = Size;
        }
    }
}

void buildSymbolicExpr(gtirb::Module &Module, const gtirb::Addr &Ea,
                       const SymbolicInfo &SymbolicInfo)
{
    gtirb::SymAttributeSet Attrs =
        buildSymbolicExpressionAttributes(Ea, SymbolicInfo.SymbolicExprAttributes);
    // SymAddr case
    if(const auto SymExpr = SymbolicInfo.SymbolicExprs.find(Ea);
       SymExpr != SymbolicInfo.SymbolicExprs.end())
    {
        gtirb::Symbol *FoundSymbol = findFirstSymbol(Module, SymExpr->Symbol);
        // FIXME: We need to handle overlapping sections here.
        addSymbolicExpressionToCodeBlock<gtirb::SymAddrConst>(Module, Ea, SymExpr->Size,
                                                              SymExpr->Addend, FoundSymbol, Attrs);
        // Symbol-Symbol case
    }
    else if(const auto SymExpr = SymbolicInfo.SymbolMinusSymbolSymbolicExprs.find(Ea);
            SymExpr != SymbolicInfo.SymbolMinusSymbolSymbolicExprs.end())
    {
        gtirb::Symbol *FoundSymbol1 = findFirstSymbol(Module, SymExpr->Symbol1);
        gtirb::Symbol *FoundSymbol2 = findFirstSymbol(Module, SymExpr->Symbol2);
        addSymbolicExpressionToCodeBlock<gtirb::SymAddrAddr>(
            Module, Ea, SymExpr->Size, static_cast<int64_t>(SymExpr->Scale), SymExpr->Offset,
            FoundSymbol2, FoundSymbol1, Attrs);
    }
}

void buildCodeSymbolicInformation(gtirb::Module &Module, souffle::SouffleProgram &Program)
{
    std::set<gtirb::Addr> Code;
    for(auto &output : *Program.getRelation("code_in_refined_block"))
    {
        gtirb::Addr EA;
        output >> EA;
        Code.insert(EA);
    }

    SymbolicInfo symbolicInfo{
        convertSortedRelation<VectorByEA<SymbolicExpr>>("symbolic_expr", Program),
        convertSortedRelation<VectorByEA<SymExprSymbolMinusSymbol>>(
            "symbolic_expr_symbol_minus_symbol", Program),
        convertSortedRelation<VectorByEA<SymbolicExprAttribute>>("symbolic_expr_attribute",
                                                                 Program)};
    std::map<gtirb::Addr, DecodedInstruction> decodedInstructions =
        recoverInstructions(Program, Code);

    for(auto &EA : Code)
    {
        const auto Inst = decodedInstructions.find(EA);
        assert(Inst != decodedInstructions.end());
        for(auto &Op : Inst->second.Operands)
        {
            if(std::get_if<ImmOp>(&Op.second))
                buildSymbolicExpr(Module, gtirb::Addr(Inst->first + Inst->second.immediateOffset),
                                  symbolicInfo);
            if(std::get_if<IndirectOp>(&Op.second))
                buildSymbolicExpr(Module,
                                  gtirb::Addr(Inst->first + Inst->second.displacementOffset),
                                  symbolicInfo);
        }
    }
}

void buildCodeBlocks(gtirb::Context &Context, gtirb::Module &Module,
                     souffle::SouffleProgram &Program)
{
    auto BlockInfo =
        convertSortedRelation<VectorByEA<BlockInformation>>("block_information", Program);

    for(auto &Tuple : *Program.getRelation("refined_block"))
    {
        gtirb::Addr BlockAddress;
        Tuple >> BlockAddress;

        if(auto Sections = Module.findSectionsOn(BlockAddress); !Sections.empty())
        {
            gtirb::Section &Section = *Sections.begin();
            uint64_t BlockSize = BlockInfo.find(BlockAddress)->size;
            if(auto It = Section.findByteIntervalsOn(BlockAddress); !It.empty())
            {
                if(gtirb::ByteInterval &ByteInterval = *It.begin(); ByteInterval.getAddress())
                {
                    uint64_t BlockOffset = BlockAddress - *ByteInterval.getAddress();
                    gtirb::DecodeMode DecodeMode = gtirb::DecodeMode::Default;
                    if((static_cast<uint64_t>(BlockAddress) & 1)
                       && (Module.getISA() == gtirb::ISA::ARM))
                    {
                        DecodeMode = gtirb::DecodeMode::Thumb;
                    }
                    ByteInterval.addBlock<gtirb::CodeBlock>(Context, BlockOffset, BlockSize,
                                                            DecodeMode);
                }
            }
        }
    }
}

// Create DataObjects for labeled objects in the BSS sections, without adding
// data to the ImageByteMap.

void buildBSS(gtirb::Context &context, gtirb::Module &module, souffle::SouffleProgram &Program)
{
    auto bssData = convertSortedRelation<std::set<gtirb::Addr>>("bss_data", Program);
    for(auto &output : *Program.getRelation("bss_section"))
    {
        std::string sectionName;
        output >> sectionName;
        const auto bss_sections = module.findSections(sectionName);
        for(const auto &bss_section : bss_sections)
        {
            // for each bss section we divide in data objects according to the bss_data markers that
            // fall within the range of the section
            auto beginning = bssData.lower_bound(bss_section.getAddress().value());
            // end points to the address at the end of the bss section
            auto end = bssData.lower_bound(*addressLimit(bss_section));
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
}

void buildDataBlocks(gtirb::Context &Context, gtirb::Module &Module,
                     souffle::SouffleProgram &Program)
{
    auto SymbolicExprs = convertSortedRelation<VectorByEA<SymbolicExpr>>("symbolic_expr", Program);
    auto SymbolMinusSymbol = convertSortedRelation<VectorByEA<SymExprSymbolMinusSymbol>>(
        "symbolic_expr_symbol_minus_symbol", Program);

    auto DataStrings = convertSortedRelation<VectorByEA<StringDataObject>>("string", Program);
    auto SymbolSpecialTypes =
        convertSortedRelation<VectorByEA<SymbolSpecialType>>("symbol_special_encoding", Program);
    auto DataBoundary =
        convertSortedRelation<std::set<gtirb::Addr>>("data_object_boundary", Program);
    auto SymbolicExprAttributes = convertSortedRelation<VectorByEA<SymbolicExprAttribute>>(
        "symbolic_expr_attribute", Program);

    std::map<gtirb::UUID, std::string> TypesTable;

    std::map<gtirb::Offset, uint64_t> SymbolicSizes;

    for(auto &Output : *Program.getRelation("initialized_data_segment"))
    {
        gtirb::Addr Begin, End;
        Output >> Begin >> End;
        // we don't create data blocks that exceed the data segment
        DataBoundary.insert(End);
        for(auto CurrentAddr = Begin; CurrentAddr < End;
            /*incremented in each case*/)
        {
            gtirb::DataBlock *DataBlock = nullptr;
            if(auto It = Module.findByteIntervalsOn(CurrentAddr); !It.empty())
            {
                if(gtirb::ByteInterval &ByteInterval = *It.begin(); ByteInterval.getAddress())
                {
                    // do not cross byte intervals.
                    DataBoundary.insert(*ByteInterval.getAddress() + ByteInterval.getSize());
                    uint64_t blockOffset = CurrentAddr - *ByteInterval.getAddress();
                    gtirb::Offset Offset = gtirb::Offset(ByteInterval.getUUID(), blockOffset);

                    // symbolic expression created from relocation
                    if(const auto SymExpr = SymbolicExprs.find(CurrentAddr);
                       SymExpr != SymbolicExprs.end())
                    {
                        DataBlock = gtirb::DataBlock::Create(Context, SymExpr->Size);
                        gtirb::Symbol *foundSymbol = findFirstSymbol(Module, SymExpr->Symbol);
                        gtirb::SymAttributeSet Attributes =
                            buildSymbolicExpressionAttributes(CurrentAddr, SymbolicExprAttributes);

                        ByteInterval.addSymbolicExpression<gtirb::SymAddrConst>(
                            blockOffset, SymExpr->Addend, foundSymbol, Attributes);
                        SymbolicSizes[Offset] = SymExpr->Size;
                    }
                    else if(const auto SymExprSymMinusSym = SymbolMinusSymbol.find(CurrentAddr);
                            SymExprSymMinusSym != SymbolMinusSymbol.end())
                    {
                        DataBlock = gtirb::DataBlock::Create(Context, SymExprSymMinusSym->Size);
                        gtirb::Symbol *Sym1 = findFirstSymbol(Module, SymExprSymMinusSym->Symbol1);
                        gtirb::Symbol *Sym2 = findFirstSymbol(Module, SymExprSymMinusSym->Symbol2);
                        gtirb::SymAttributeSet Attributes =
                            buildSymbolicExpressionAttributes(CurrentAddr, SymbolicExprAttributes);

                        ByteInterval.addSymbolicExpression<gtirb::SymAddrAddr>(
                            blockOffset, static_cast<int64_t>(SymExprSymMinusSym->Scale),
                            SymExprSymMinusSym->Offset, Sym2, Sym1, Attributes);
                        SymbolicSizes[Offset] = SymExprSymMinusSym->Size;
                    }
                    else
                        // string
                        if(const auto S = DataStrings.find(CurrentAddr); S != DataStrings.end())
                    {
                        DataBlock = gtirb::DataBlock::Create(Context, S->End - CurrentAddr);
                        TypesTable[DataBlock->getUUID()] = S->Encoding;
                    }
                    else
                    {
                        // Accumulate region with no symbols into a single DataBlock.
                        auto NextDataObject = DataBoundary.lower_bound(CurrentAddr + 1);
                        DataBlock =
                            gtirb::DataBlock::Create(Context, *NextDataObject - CurrentAddr);
                    }
                    // symbol special types
                    const auto specialType = SymbolSpecialTypes.find(CurrentAddr);
                    if(specialType != SymbolSpecialTypes.end())
                        TypesTable[DataBlock->getUUID()] = specialType->Type;
                    ByteInterval.addBlock(blockOffset, DataBlock);
                    CurrentAddr += DataBlock->getSize();
                }
            }
            else
            {
                std::cerr << "ByteInterval at address " << CurrentAddr << " not found" << std::endl;
                exit(1);
            }
        }
    }
    buildBSS(Context, Module, Program);
    Module.addAuxData<gtirb::schema::Encodings>(std::move(TypesTable));
    Module.addAuxData<gtirb::schema::SymbolicExpressionSizes>(std::move(SymbolicSizes));
}

void buildAlignments(gtirb::Module &Module, souffle::SouffleProgram &Program)
{
    auto Alignments = convertSortedRelation<VectorByEA<Alignment>>("alignment", Program);

    auto *Alignment = Module.getAuxData<gtirb::schema::Alignment>();
    if(!Alignment)
    {
        // Create one if none exists.
        std::map<gtirb::UUID, uint64_t> Tmp;
        Module.addAuxData<gtirb::schema::Alignment>(std::move(Tmp));
        Alignment = Module.getAuxData<gtirb::schema::Alignment>();
    }

    for(auto &AlignInfo : Alignments)
    {
        if(auto BlockIt = Module.findBlocksAt(AlignInfo.EA); !BlockIt.empty())
        {
            gtirb::Node &Block = BlockIt.front();
            (*Alignment)[Block.getUUID()] = AlignInfo.Num;
        }
    }
}

void connectSymbolsToBlocks(gtirb::Context &Context, gtirb::Module &Module,
                            souffle::SouffleProgram &Program)
{
    auto *Alignment = Module.getAuxData<gtirb::schema::Alignment>();
    auto *SymbolInfo = Module.getAuxData<gtirb::schema::ElfSymbolInfo>();

    // Assign communal symbols (.comm) to ProxyBlocks; communal variables are
    // allocated by the linker and are not initialized.
    if(SymbolInfo)
    {
        for(auto [Uuid, Info] : *SymbolInfo)
        {
            uint64_t SectionIndex = std::get<4>(Info);
            constexpr uint64_t SHN_COMMON = 0xfff2;
            if(SectionIndex == SHN_COMMON)
            {
                gtirb::Node *Node = gtirb::Node::getByUUID(Context, Uuid);
                if(auto *Symbol = gtirb::dyn_cast_or_null<gtirb::Symbol>(Node);
                   Symbol && Symbol->getAddress())
                {
                    // Alignment is stored in the symbol's value field.
                    if(Alignment)
                    {
                        (*Alignment)[Uuid] = static_cast<uint64_t>(*Symbol->getAddress());
                    }
                    Symbol->setReferent(Module.addProxyBlock(Context));
                }
            }
        }
    }
    for(auto &T : *Program.getRelation("symbol_at_end"))
    {
        gtirb::Addr EA;
        std::string SymbolName;
        T >> EA >> SymbolName;
        if(gtirb::Symbol *Sym = findSymbol(Module, EA, SymbolName))
        {
            Sym->setAtEnd(true);
        }
    }
    for(auto &T : *Program.getRelation("symbol_before_section_beg"))
    {
        gtirb::Addr EA, NewEA;
        std::string SymbolName;
        T >> EA >> SymbolName >> NewEA;
        if(gtirb::Symbol *Sym = findSymbol(Module, EA, SymbolName))
        {
            Sym->setAddress(NewEA);
            std::cerr << "WARNING: Moving symbol to first block of section: " << Sym->getName()
                      << std::endl;
        }
    }

    std::map<gtirb::Symbol *, std::tuple<gtirb::Node *, bool>> ConnectToBlock;
    for(auto &Symbol : Module.symbols_by_addr())
    {
        if(Symbol.getAddress())
        {
            gtirb::Addr Addr = *Symbol.getAddress();
            if(Symbol.getAtEnd())
            {
                if(auto BlockIt = Module.findBlocksOn(Addr - 1); !BlockIt.empty())
                {
                    gtirb::Node &Block = BlockIt.front();
                    ConnectToBlock[&Symbol] = {&Block, true};
                    continue;
                }
            }
            else
            {
                if(auto BlockIt = Module.findBlocksAt(Addr); !BlockIt.empty())
                {
                    gtirb::Node &Block = BlockIt.front();
                    ConnectToBlock[&Symbol] = {&Block, false};
                    continue;
                }

                if((Module.getISA() == gtirb::ISA::ARM) && ((static_cast<uint64_t>(Addr) & 1) == 0))
                {
                    // If a Thumb block starts here, connect to it.
                    // CodeBlocks still are located at +1 until shiftThumbBlocks() executes.
                    if(auto It = Module.findCodeBlocksAt(Addr + 1); !It.empty())
                    {
                        gtirb::CodeBlock &Block = It.front();
                        ConnectToBlock[&Symbol] = {&Block, false};
                        continue;
                    }
                }
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
        }
    }
    for(auto [Symbol, T] : ConnectToBlock)
    {
        auto [Node, AtEnd] = T;
        if(gtirb::CodeBlock *CodeBlock = gtirb::dyn_cast_or_null<gtirb::CodeBlock>(Node))
        {
            Symbol->setReferent(CodeBlock);
            Symbol->setAtEnd(AtEnd);
        }
        else if(gtirb::DataBlock *DataBlock = gtirb::dyn_cast_or_null<gtirb::DataBlock>(Node))
        {
            Symbol->setReferent(DataBlock);
            Symbol->setAtEnd(AtEnd);
        }
    }
    // Connect remaining undefined external symbols to `ProxyBlocks'.
    auto *SymbolForwarding = Module.getAuxData<gtirb::schema::SymbolForwarding>();
    if(SymbolForwarding && SymbolInfo)
    {
        for(auto Forward : *SymbolForwarding)
        {
            gtirb::Node *Node = gtirb::Node::getByUUID(Context, std::get<1>(Forward));
            if(auto *Symbol = gtirb::dyn_cast_or_null<gtirb::Symbol>(Node))
            {
                if(Symbol->hasReferent())
                {
                    continue;
                }
                if(auto It = SymbolInfo->find(Symbol->getUUID()); It != SymbolInfo->end())
                {
                    if(uint64_t SectionIndex = std::get<4>(It->second); SectionIndex == 0)
                    {
                        gtirb::ProxyBlock *ExternalBlock = Module.addProxyBlock(Context);
                        Symbol->setReferent(ExternalBlock);
                    }
                }
            }
        }
    }
}

void buildFunctions(gtirb::Module &Module, souffle::SouffleProgram &Program)
{
    std::map<gtirb::UUID, std::set<gtirb::UUID>> FunctionEntries;
    std::map<gtirb::Addr, gtirb::UUID> FunctionEntry2Function;
    std::map<gtirb::UUID, gtirb::UUID> FunctionNames;
    boost::uuids::random_generator Generator;

    for(auto &T : *Program.getRelation("function_inference.function_entry_name"))
    {
        gtirb::Addr FunctionEntry;
        std::string FunctionName;
        T >> FunctionEntry >> FunctionName;

        auto BlockRange = Module.findCodeBlocksAt(FunctionEntry);
        if(!BlockRange.empty())
        {
            const gtirb::UUID &EntryBlockUUID = BlockRange.begin()->getUUID();
            gtirb::UUID FunctionUUID = Generator();

            FunctionEntry2Function[FunctionEntry] = FunctionUUID;
            FunctionEntries[FunctionUUID].insert(EntryBlockUUID);

            gtirb::Symbol *FunctionNameSymbol = findFirstSymbol(Module, FunctionName);

            FunctionNames.insert({FunctionUUID, FunctionNameSymbol->getUUID()});
        }
    }

    std::map<gtirb::UUID, std::set<gtirb::UUID>> FunctionBlocks;
    for(auto &T : *Program.getRelation("function_inference.in_function"))
    {
        gtirb::Addr BlockAddr, FunctionEntryAddr;
        T >> BlockAddr >> FunctionEntryAddr;
        auto BlockRange = Module.findCodeBlocksOn(BlockAddr);
        if(!BlockRange.empty())
        {
            gtirb::CodeBlock *Block = &*BlockRange.begin();
            gtirb::UUID FunctionEntryUUID = FunctionEntry2Function[FunctionEntryAddr];
            FunctionBlocks[FunctionEntryUUID].insert(Block->getUUID());
        }
    }

    Module.addAuxData<gtirb::schema::FunctionEntries>(std::move(FunctionEntries));
    Module.addAuxData<gtirb::schema::FunctionBlocks>(std::move(FunctionBlocks));
    Module.addAuxData<gtirb::schema::FunctionNames>(std::move(FunctionNames));
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

void buildCFG(gtirb::Context &Context, gtirb::Module &Module, souffle::SouffleProgram &Program)
{
    auto &Cfg = Module.getIR()->getCFG();
    for(auto &Output : *Program.getRelation("cfg_edge"))
    {
        gtirb::Addr SrcAddr, DestAddr;
        std::string Conditional, Indirect, Type;
        Output >> SrcAddr >> DestAddr >> Conditional >> Indirect >> Type;

        // ddisasm guarantees that these blocks exist
        const gtirb::CodeBlock *Src = &*Module.findCodeBlocksOn(SrcAddr).begin();
        const gtirb::CodeBlock *Dest = &*Module.findCodeBlocksOn(DestAddr).begin();

        auto IsConditional = Conditional == "true" ? gtirb::ConditionalEdge::OnTrue
                                                   : gtirb::ConditionalEdge::OnFalse;
        auto IsIndirect =
            Indirect == "true" ? gtirb::DirectEdge::IsIndirect : gtirb::DirectEdge::IsDirect;
        gtirb::EdgeType edgeType = getEdgeType(Type);

        auto E = addEdge(Src, Dest, Cfg);
        Cfg[*E] = std::make_tuple(IsConditional, IsIndirect, edgeType);
    }
    auto *TopBlock = Module.addProxyBlock(Context);
    for(auto &Output : *Program.getRelation("cfg_edge_to_top"))
    {
        gtirb::Addr SrcAddr;
        std::string Conditional, Type;
        Output >> SrcAddr >> Conditional >> Type;
        const gtirb::CodeBlock *Src = &*Module.findCodeBlocksOn(SrcAddr).begin();
        auto isConditional = Conditional == "true" ? gtirb::ConditionalEdge::OnTrue
                                                   : gtirb::ConditionalEdge::OnFalse;
        gtirb::EdgeType EdgeType = getEdgeType(Type);
        auto E = addEdge(Src, TopBlock, Cfg);
        Cfg[*E] = std::make_tuple(isConditional, gtirb::DirectEdge::IsIndirect, EdgeType);
    }
    for(auto &T : *Program.getRelation("cfg_edge_to_symbol"))
    {
        gtirb::Addr EA;
        std::string Name;
        std::string Conditional, Indirect, Type;
        T >> EA >> Name >> Conditional >> Indirect >> Type;

        const gtirb::CodeBlock *CodeBlock = &*Module.findCodeBlocksOn(EA).begin();
        auto It = Module.findSymbols(Name);
        if(It.empty())
        {
            std::cerr << "WARNING: failed to find symbols for " << Name << " in cfg_edge_to_symbol("
                      << EA << "," << Name << "," << Type << ")\n";
            continue;
        }

        gtirb::Symbol &Symbol = *It.begin();
        gtirb::CfgNode *ExternalBlock = Symbol.getReferent<gtirb::ProxyBlock>();
        if(!ExternalBlock)
        {
            gtirb::CodeBlock *TgtCodeBlock = Symbol.getReferent<gtirb::CodeBlock>();
            if(TgtCodeBlock)
            {
                std::cerr
                    << "WARNING: symbol " << Name
                    << " expected to be undefined, but it is attached to code block at address"
                    << TgtCodeBlock->getAddress() << std::endl;
                ExternalBlock = TgtCodeBlock;
            }
            else
            {
                // Create a ProxyBlock if the symbol does not already reference one.
                gtirb::ProxyBlock *NewProxyBlock = Module.addProxyBlock(Context);
                Symbol.setReferent(NewProxyBlock);
                ExternalBlock = NewProxyBlock;
            }
        }

        auto IsConditional = Conditional == "true" ? gtirb::ConditionalEdge::OnTrue
                                                   : gtirb::ConditionalEdge::OnFalse;
        auto IsIndirect =
            Indirect == "true" ? gtirb::DirectEdge::IsIndirect : gtirb::DirectEdge::IsDirect;
        gtirb::EdgeType EdgeType = getEdgeType(Type);
        auto E = addEdge(CodeBlock, ExternalBlock, Cfg);
        Cfg[*E] = {IsConditional, IsIndirect, EdgeType};
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

void buildCfiDirectives(gtirb::Module &Module, souffle::SouffleProgram &Program)
{
    std::map<gtirb::Offset, std::vector<std::tuple<std::string, std::vector<int64_t>, gtirb::UUID>>>
        CfiDirectives;
    for(auto &output : *Program.getRelation("cfi_directive"))
    {
        gtirb::Addr BlockAddr;
        std::string Directive, Reference;
        uint64_t Disp, LocalIndex, NumOperands;
        int64_t Op1, Op2;
        output >> BlockAddr >> Disp >> LocalIndex >> Directive >> Reference >> NumOperands >> Op1
            >> Op2;
        std::vector<int64_t> Operands;
        // cfi_escape directives have a sequence of bytes as operands (the raw bytes of the
        // dwarf instruction). The address 'Reference' points to these bytes.
        if(Directive == ".cfi_escape")
        {
            gtirb::Addr BytesLocation = gtirb::Addr(Op1);
            if(const auto It = Module.findByteIntervalsOn(BytesLocation); !It.empty())
            {
                if(const gtirb::ByteInterval &Interval = *It.begin(); Interval.getAddress())
                {
                    auto Begin =
                        Interval.bytes_begin<uint8_t>() + (BytesLocation - *Interval.getAddress());
                    auto End = Begin + NumOperands;
                    for(uint8_t Byte : boost::make_iterator_range(Begin, End))
                    {
                        Operands.push_back(static_cast<int64_t>(Byte));
                    }
                }
            }
        }
        else
        {
            if(NumOperands > 0)
                Operands.push_back(Op1);
            if(NumOperands > 1)
                Operands.push_back(Op2);
        }

        auto BlockRange = Module.findCodeBlocksOn(BlockAddr);
        if(BlockRange.begin() != BlockRange.end() && BlockAddr == BlockRange.begin()->getAddress())
        {
            gtirb::Offset Offset(BlockRange.begin()->getUUID(), Disp);
            if(CfiDirectives[Offset].size() < LocalIndex + 1)
                CfiDirectives[Offset].resize(LocalIndex + 1);

            if(Directive != ".cfi_escape" && Reference != "")
            {
                // for normal directives (not cfi_escape) the Reference points to a symbol.
                gtirb::Symbol *Symbol = findFirstSymbol(Module, Reference);
                CfiDirectives[Offset][LocalIndex] =
                    std::make_tuple(Directive, Operands, Symbol->getUUID());
            }
            else
            {
                gtirb::UUID Uuid;
                CfiDirectives[Offset][LocalIndex] = std::make_tuple(Directive, Operands, Uuid);
            }
        }
    }
    Module.addAuxData<gtirb::schema::CfiDirectives>(std::move(CfiDirectives));
}

void buildSehTable(gtirb::Module &Module, souffle::SouffleProgram &Program)
{
    if(Module.getFileFormat() != gtirb::FileFormat::PE)
    {
        return;
    }

    std::set<gtirb::UUID> Handlers;

    for(auto &T : *Program.getRelation("pe_exception_handler"))
    {
        gtirb::Addr EA;
        T >> EA;

        if(const auto It = Module.findCodeBlocksAt(EA); !It.empty())
        {
            gtirb::CodeBlock &Block = *It.begin();
            Handlers.insert(Block.getUUID());
        }
    };

    Module.addAuxData<gtirb::schema::PeSafeExceptionHandlers>(std::move(Handlers));
}

void buildPadding(gtirb::Module &Module, souffle::SouffleProgram &Program)
{
    std::map<gtirb::Offset, uint64_t> Padding;
    for(auto &Output : *Program.getRelation("padding"))
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

void buildComments(gtirb::Module &Module, souffle::SouffleProgram &Program, bool SelfDiagnose)
{
    std::map<gtirb::Offset, std::string> Comments;
    auto *data_access_pattern = Program.getRelation("data_access_pattern");
    if(data_access_pattern)
    {
        for(auto &Output : *data_access_pattern)
        {
            gtirb::Addr Ea;
            uint64_t Size, From;
            int64_t Multiplier;
            Output >> Ea >> Size >> Multiplier >> From;
            std::ostringstream NewComment;
            NewComment << "data_access(" << Size << ", " << Multiplier << ", " << std::hex << From
                       << std::dec << ")";
            updateComment(Module, Comments, Ea, NewComment.str());
        }
    }

    auto *preferred_data_access = Program.getRelation("preferred_data_access");
    if(preferred_data_access)
    {
        for(auto &Output : *preferred_data_access)
        {
            gtirb::Addr Ea;
            uint64_t Size, DataAccess;
            Output >> Ea >> Size >> DataAccess;
            std::ostringstream NewComment;
            NewComment << "preferred_data_access(" << Size << ", " << std::hex << DataAccess
                       << std::dec << ")";
            updateComment(Module, Comments, Ea, NewComment.str());
        }
    }

    auto *best_value_reg = Program.getRelation("best_value_reg");
    if(best_value_reg)
    {
        for(auto &Output : *best_value_reg)
        {
            gtirb::Addr Ea, EaOrigin;
            std::string Reg, Type;
            int64_t Multiplier, Offset;
            Output >> Ea >> Reg >> EaOrigin >> Multiplier >> Offset >> Type;
            std::ostringstream NewComment;
            NewComment << Reg << "=X*" << Multiplier << "+" << std::hex << Offset << std::dec
                       << " type(" << Type << ")";
            updateComment(Module, Comments, Ea, NewComment.str());
        }
    }

    auto *value_reg = Program.getRelation("value_reg");
    if(value_reg)
    {
        for(auto &Output : *value_reg)
        {
            gtirb::Addr Ea, Ea2;
            std::string Reg, Reg2;
            int64_t Multiplier, Offset;
            Output >> Ea >> Reg >> Ea2 >> Reg2 >> Multiplier >> Offset;
            std::ostringstream NewComment;
            NewComment << Reg << "=(" << Reg2 << "," << std::hex << Ea2 << std::dec << ")*"
                       << Multiplier << "+" << std::hex << Offset << std::dec;
            updateComment(Module, Comments, Ea, NewComment.str());
        }
    }

    auto *moved_label_class = Program.getRelation("moved_label_class");
    if(moved_label_class)
    {
        for(auto &Output : *moved_label_class)
        {
            gtirb::Addr Ea;
            uint64_t OpIndex;
            std::string Type;

            Output >> Ea >> OpIndex >> Type;
            std::ostringstream NewComment;
            NewComment << " moved label-" << Type;
            updateComment(Module, Comments, Ea, NewComment.str());
        }
    }

    auto *reg_def_use_def_used = Program.getRelation("reg_def_use.def_used");
    if(reg_def_use_def_used)
    {
        for(auto &Output : *reg_def_use_def_used)
        {
            gtirb::Addr EaUse, EaDef;
            uint64_t Index;
            std::string Reg;
            Output >> EaDef >> Reg >> EaUse >> Index;
            std::ostringstream NewComment;
            NewComment << "def(" << Reg << ", " << std::hex << EaDef << std::dec << ")";
            updateComment(Module, Comments, EaUse, NewComment.str());
        }
    }

    auto *missed_jump_table = Program.getRelation("missed_jump_table");
    if(missed_jump_table)
    {
        for(auto &Output : *missed_jump_table)
        {
            gtirb::Addr Ea;
            Output >> Ea;
            std::ostringstream NewComment;
            NewComment << "missed_jump_table";
            updateComment(Module, Comments, Ea, NewComment.str());
        }
    }

    auto *reg_has_base_image = Program.getRelation("reg_has_base_image");
    if(reg_has_base_image)
    {
        for(auto &Output : *reg_has_base_image)
        {
            gtirb::Addr Ea;
            std::string Reg;
            Output >> Ea >> Reg;
            std::ostringstream NewComment;
            NewComment << "hasImageBase(" << Reg << ")";
            updateComment(Module, Comments, Ea, NewComment.str());
        }
    }

    auto *reg_has_got = Program.getRelation("reg_has_got");
    if(reg_has_got)
    {
        for(auto &T : *reg_has_got)
        {
            gtirb::Addr EA;
            std::string Reg;
            T >> EA >> Reg;
            std::ostringstream Comment;
            Comment << "GOT(" << Reg << ")";
            updateComment(Module, Comments, EA, Comment.str());
        }
    }
    if(SelfDiagnose)
    {
        for(auto &Output : *Program.getRelation("false_positive"))
        {
            gtirb::Addr Ea;
            Output >> Ea;
            updateComment(Module, Comments, Ea, "false positive");
        }
        for(auto &Output : *Program.getRelation("false_negative"))
        {
            gtirb::Addr Ea;
            Output >> Ea;
            updateComment(Module, Comments, Ea, "false negative");
        }
        for(auto &Output : *Program.getRelation("bad_symbol_constant"))
        {
            gtirb::Addr Ea;
            uint64_t Index;
            Output >> Ea >> Index;
            std::ostringstream NewComment;
            NewComment << "bad_symbol_constant(" << Index << ")";
            updateComment(Module, Comments, Ea, NewComment.str());
        }
    }
    Module.addAuxData<gtirb::schema::Comments>(std::move(Comments));
}

void updateEntryPoint(gtirb::Module &module, souffle::SouffleProgram &Program)
{
    for(auto &output : *Program.getRelation("entry_point"))
    {
        gtirb::Addr ea;
        output >> ea;

        if(const auto it = module.findCodeBlocksAt(ea); !it.empty())
        {
            module.setEntryPoint(&*it.begin());
        }
    }

    if(module.getFileFormat() != gtirb::FileFormat::RAW && !module.getEntryPoint())
    {
        std::cerr << "WARNING: Failed to set module entry point.\n";
    }
}

void buildDynamicAuxdata(gtirb::Module &Module)
{
    auto DynamicEntries = Module.getAuxData<gtirb::schema::DynamicEntries>();
    if(DynamicEntries)
    {
        for(auto &[Key, Value] : *DynamicEntries)
        {
            if(Key == "INIT")
            {
                auto CB = Module.findCodeBlocksAt(gtirb::Addr(Value));
                if(CB.empty())
                {
                    std::cerr << "WARNING: No code block created at DT_INIT\n";
                }
                else
                {
                    gtirb::UUID UUID = CB.begin()->getUUID();
                    Module.addAuxData<gtirb::schema::ElfDynamicInit>(std::move(UUID));
                }
            }
            else if(Key == "FINI")
            {
                auto CB = Module.findCodeBlocksAt(gtirb::Addr(Value));
                if(CB.empty())
                {
                    std::cerr << "WARNING: No code block created at DT_FINI\n";
                    continue;
                }
                else
                {
                    gtirb::UUID UUID = CB.begin()->getUUID();
                    Module.addAuxData<gtirb::schema::ElfDynamicFini>(std::move(UUID));
                }
            }
        }
    }
}

void shiftThumbBlocks(gtirb::Module &Module)
{
    // Find thumb code blocks.
    std::vector<std::tuple<gtirb::CodeBlock *, uint64_t>> ThumbBlocks;
    for(auto &BI : Module.byte_intervals())
    {
        for(auto &CodeBlock : BI.code_blocks())
        {
            uint64_t Offset = CodeBlock.getOffset();
            if(Offset & 1)
            {
                ThumbBlocks.emplace_back(&CodeBlock, Offset);
            }
        }
    }
    // Shift thumb code blocks.
    for(auto [CodeBlock, Offset] : ThumbBlocks)
    {
        gtirb::ChangeStatus Status;
        gtirb::ByteInterval *BI = CodeBlock->getByteInterval();

        // Relocate the CodeBlock at the original offset less one.
        Status = BI->addBlock(Offset - 1, CodeBlock);
        if(Status != gtirb::ChangeStatus::Accepted)
        {
            std::cerr << "Failed to add thumb block: " << BI->getAddress() << "\n";
        }
    }
}

void buildArchInfo(gtirb::Module &Module, souffle::SouffleProgram &Program)
{
    if(Module.getISA() == gtirb::ISA::ARM)
    {
        // ArchInfo may have been extracted from the .ARM.attributes section.
        auto *ArchInfo0 = Module.getAuxData<gtirb::schema::ArchInfo>();
        if(!ArchInfo0)
        {
            // If the information is not found, see if the datalog inferred any
            // arch information.
            std::map<std::string, std::string> ArchInfo;
            for(auto &output : *Program.getRelation("inferred_arch_info"))
            {
                std::string Key;
                std::string Value;
                output >> Key >> Value;

                auto It = ArchInfo.find(Key);
                if(It != ArchInfo.end())
                {
                    std::cerr << "WARNING: Conflicting values for ArchInfo " << Key << ": "
                              << It->second << ", " << Value << "\n";
                }
                ArchInfo[Key] = Value;
            }

            if(ArchInfo.size() > 0)
            {
                Module.addAuxData<gtirb::schema::ArchInfo>(std::move(ArchInfo));
            }
        }
    }
}

void removePreviousModuleContent(gtirb::Module &Module)
{
    for(auto &Bi : Module.byte_intervals())
    {
        std::vector<gtirb::CodeBlock *> CodeToRemove;
        for(auto &Block : Bi.code_blocks())
        {
            CodeToRemove.push_back(&Block);
        }
        for(auto Block : CodeToRemove)
        {
            Bi.removeBlock(Block);
        }
        std::vector<gtirb::DataBlock *> DataToRemove;
        for(auto &Block : Bi.data_blocks())
        {
            DataToRemove.push_back(&Block);
        }
        for(auto Block : DataToRemove)
        {
            Bi.removeBlock(Block);
        }
        std::vector<uint64_t> SymExprOffset;
        for(auto SymExpr : Bi.symbolic_expressions())
        {
            SymExprOffset.push_back(SymExpr.getOffset());
        }
        for(auto Offset : SymExprOffset)
        {
            Bi.removeSymbolicExpression(Offset);
        }
    }
}
void disassembleModule(gtirb::Context &Context, gtirb::Module &Module,
                       souffle::SouffleProgram &Program, bool SelfDiagnose)
{
    removeSectionSymbols(Context, Module);
    removeEntryPoint(Module);
    removePreviousModuleContent(Module);
    buildInferredSymbols(Context, Module, Program);
    buildSymbolForwarding(Context, Module, Program);
    buildCodeBlocks(Context, Module, Program);
    buildDataBlocks(Context, Module, Program);
    buildAlignments(Module, Program);
    buildCodeSymbolicInformation(Module, Program);
    buildCfiDirectives(Module, Program);
    buildSehTable(Module, Program);
    expandSymbolForwarding(Module, Program);
    buildFunctions(Module, Program);
    // This should be done after creating all the symbols.
    connectSymbolsToBlocks(Context, Module, Program);
    // These functions should not create additional symbols.
    buildCFG(Context, Module, Program);
    buildPadding(Module, Program);
    buildComments(Module, Program, SelfDiagnose);
    buildDynamicAuxdata(Module);
    updateEntryPoint(Module, Program);
    removeSymbolVersionsFromNames(Module);
    buildArchInfo(Module, Program);
    if(Module.getISA() == gtirb::ISA::ARM)
    {
        shiftThumbBlocks(Module);
    }
}

void performSanityChecks(AnalysisPassResult &Result, souffle::SouffleProgram &Program,
                         bool selfDiagnose, bool ignoreErrors)
{
    std::list<std::string> &Messages = ignoreErrors ? Result.Warnings : Result.Errors;
    if(selfDiagnose)
    {
        Result.Warnings.push_back(
            "Perfoming self diagnose (this will only give the right results if "
            "the target program contains all the relocation information)");
        auto falsePositives = Program.getRelation("false_positive");
        if(falsePositives->size() > 0)
        {
            std::stringstream ErrMsg;
            ErrMsg << "False positives: " << falsePositives->size();
            Messages.push_back(ErrMsg.str());
        }
        auto falseNegatives = Program.getRelation("false_negative");
        if(falseNegatives->size() > 0)
        {
            std::stringstream ErrMsg;
            ErrMsg << "False negatives: " << falseNegatives->size();
            Messages.push_back(ErrMsg.str());
        }
        auto badSymbolCnt = Program.getRelation("bad_symbol_constant");
        if(badSymbolCnt->size() > 0)
        {
            std::stringstream ErrMsg;
            ErrMsg << "Bad symbol constants: " << badSymbolCnt->size();
            Messages.push_back(ErrMsg.str());
        }
    }
    auto blockOverlap = Program.getRelation("block_still_overlap");
    for(auto &output : *blockOverlap)
    {
        std::stringstream ErrMsg;
        uint64_t Block1, Block2, Size1, Size2;
        std::string BlockKind1, BlockKind2;
        output >> Block1 >> BlockKind1 >> Size1 >> Block2 >> BlockKind2 >> Size2;
        ErrMsg << "The following code blocks have equal points and remain overlapping: \n"
               << "\t" << BlockKind1 << " at 0x" << std::hex << Block1 << ", " << std::dec << Size1
               << " bytes\n"
               << "\t" << BlockKind2 << " at 0x" << std::hex << Block2 << ", " << std::dec << Size2
               << " bytes\n"
               << "\n\tTo select one of the blocks, re-run ddisasm with hints, e.g.:\n"
               << "\t$ printf 'disassembly.known_block\\t0x" << std::hex << Block1 << "\\t"
               << BlockKind1 << "\\t" << std::dec << Size1 << "\\thint\\n' >> hints.csv\n"
               << "\t$ ddisasm --hints ./hints.csv [...]\n";
        Messages.push_back(ErrMsg.str());
    }

    auto intervalScheduleTie = Program.getRelation("interval_schedule_tie");
    for(auto &output : *intervalScheduleTie)
    {
        std::stringstream WarnMsg;
        uint64_t StartA, BlockA, SizeA, StartB, BlockB, SizeB;
        std::string BlockKindA, BlockKindB;
        output >> BlockA >> BlockKindA >> SizeA >> BlockB >> BlockKindB >> SizeB;
        WarnMsg << "The following block intervals have equal weights (interval scheduling): \n"
                << "\t" << BlockKindA << " at 0x" << std::hex << BlockA << ", " << std::dec << SizeA
                << " bytes (selected)\n"
                << "\t" << BlockKindB << " at 0x" << std::hex << BlockB << ", " << std::dec << SizeB
                << " bytes (not selected)\n"
                << "\n\tTo select the other block, re-run ddisasm with hints, e.g.:\n"
                << "\t$ printf 'disassembly.known_block\\t0x" << std::hex << BlockB << "\\t"
                << BlockKindB << "\\t" << std::dec << SizeB << "\\thint\\n' >> hints.csv\n"
                << "\t$ ddisasm --hints ./hints.csv [...]\n";
        Result.Warnings.push_back(WarnMsg.str());
    }

    auto MissingWeight = Program.getRelation("missing_weight");
    for(auto &Output : *MissingWeight)
    {
        std::stringstream ErrorMsg;
        std::string Missing;
        Output >> Missing;
        ErrorMsg << "Missing Weight:" << Missing << std::endl;
        Messages.push_back(ErrorMsg.str());
    }

    auto UnexpectedNegativeWeight = Program.getRelation("unexpected_negative_heuristic_weight");
    for(auto &Output : *UnexpectedNegativeWeight)
    {
        std::stringstream WarnMsg;
        std::string Heuristic;
        int64_t Weight;
        Output >> Heuristic >> Weight;
        WarnMsg << Heuristic << " was assigned a negative weight " << Weight
                << " but it is designed as a positive heuristic.\n"
                << "Positive heuristics are only computed for unresolved blocks "
                << "but will not cause blocks to become unresolved." << std::endl;
        Result.Warnings.push_back(WarnMsg.str());
    }
}
