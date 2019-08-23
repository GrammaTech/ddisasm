//===- disasm_main.cpp ------------------------------------------*- C++ -*-===//
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
#include <PrettyPrinter.h>
#include <souffle/CompiledSouffle.h>
#include <souffle/SouffleInterface.h>
#include <boost/program_options.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <cstddef>
#include <fstream>
#include <gtirb/gtirb.hpp>
#include <iostream>
#include <string>
#include <utility>
#include <vector>
#include "BinaryReader.h"
#include "Dl_decoder.h"
#include "ExceptionDecoder.h"
#include "LIEFBinaryReader.h"

namespace po = boost::program_options;
using namespace std::rel_ops;

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
    DecodedInstruction(gtirb::Addr ea) : EA(ea)
    {
    }

    DecodedInstruction(souffle::tuple &tuple)
    {
        assert(tuple.size() == 10);

        std::string prefix, opcode;

        tuple >> EA >> Size >> prefix >> opcode >> Op1 >> Op2 >> Op3 >> Op4 >> immediateOffset
            >> displacementOffset;
    };

    gtirb::Addr EA{0};
    uint64_t Size{0};
    uint64_t Op1{0};
    uint64_t Op2{0};
    uint64_t Op3{0};
    uint64_t Op4{0};
    int64_t immediateOffset{0};
    int64_t displacementOffset{0};
};

struct OpRegdirect
{
    OpRegdirect(souffle::tuple &tuple)
    {
        assert(tuple.size() == 2);
        tuple >> N >> Register;
    };

    uint64_t N{0};
    std::string Register;
};

struct OpImmediate
{
    OpImmediate(uint64_t n) : N(n)
    {
    }

    OpImmediate(souffle::tuple &tuple)
    {
        assert(tuple.size() == 2);
        tuple >> N >> Immediate;
    };

    uint64_t N{0};
    int64_t Immediate{0};
};

struct OpIndirect
{
    OpIndirect(uint64_t n) : N(n)
    {
    }

    OpIndirect(souffle::tuple &tuple)
    {
        assert(tuple.size() == 7);

        tuple >> N >> SReg >> Reg1 >> Reg2 >> Multiplier >> Offset >> Size;
    }

    uint64_t N{0};
    std::string SReg;
    std::string Reg1;
    std::string Reg2;
    int64_t Multiplier{0};
    int64_t Offset{0};
    uint64_t Size{0};
};

struct CodeInBlock
{
    CodeInBlock(souffle::tuple &tuple)
    {
        assert(tuple.size() == 2);

        tuple >> EA >> this->BlockAddress;
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
        assert(tuple.size() == 2);
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
        tuple >> EA >> OpNum >> Offset1 >> Offset2;
    };

    gtirb::Addr EA{0};
    uint64_t OpNum{0};
    int64_t Offset1{0};
    int64_t Offset2{0};
};

struct MovedDataLabel
{
    MovedDataLabel(gtirb::Addr ea) : EA(ea)
    {
    }

    MovedDataLabel(souffle::tuple &tuple)
    {
        assert(tuple.size() == 4);
        tuple >> EA >> Size >> Offset1 >> Offset2;
    };

    gtirb::Addr EA{0};
    uint64_t Size{0};
    int64_t Offset1{0};
    int64_t Offset2{0};
};

struct SymbolicExpression
{
    SymbolicExpression(gtirb::Addr ea) : EA(ea)
    {
    }
    SymbolicExpression(souffle::tuple &tuple)
    {
        assert(tuple.size() == 4);
        tuple >> EA >> OpNum;
    };

    gtirb::Addr EA{0};
    uint64_t OpNum{0};
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
class VectorByEA
{
public:
    explicit VectorByEA() = default;
    using const_iterator = typename std::vector<T>::const_iterator;
    void sort()
    {
        std::sort(this->contents.begin(), this->contents.end(),
                  [](const auto &left, const auto &right) { return left.EA < right.EA; });
    }

    std::pair<const_iterator, const_iterator> equal_range(gtirb::Addr ea) const
    {
        T key(ea);
        return std::equal_range(
            this->contents.begin(), this->contents.end(), key,
            [](const auto &left, const auto &right) { return left.EA < right.EA; });
    }

    const T *find(gtirb::Addr ea) const
    {
        auto inst = this->equal_range(ea);
        if(inst.first != this->contents.end() && inst.first->EA == ea)
        {
            return &*inst.first;
        }
        else
        {
            return nullptr;
        }
    }

    std::vector<T> contents;
};

template <typename T>
class VectorByN
{
public:
    explicit VectorByN() = default;
    using const_iterator = typename std::vector<T>::const_iterator;
    void sort()
    {
        std::sort(this->contents.begin(), this->contents.end(),
                  [](const auto &left, const auto &right) { return left.N < right.N; });
    }

    std::pair<const_iterator, const_iterator> equal_range(uint64_t n) const
    {
        T key(n);
        return std::equal_range(
            this->contents.begin(), this->contents.end(), key,
            [](const auto &left, const auto &right) { return left.N < right.N; });
    }

    const T *find(uint64_t n) const
    {
        auto inst = this->equal_range(n);
        if(inst.first != this->contents.end() && inst.first->N == n)
        {
            return &*inst.first;
        }
        else
        {
            return nullptr;
        }
    }

    std::vector<T> contents;
};

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
static std::vector<T> convertRelation(const std::string &relation, souffle::SouffleProgram *prog)
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
    auto *r = prog->getRelation(relation);
    std::transform(r->begin(), r->end(), std::back_inserter(result), [](auto &tuple) {
        gtirb::Addr addr;
        tuple >> addr;
        return addr;
    });
    return result;
}

template <typename T>
static T convertSortedRelation(const std::string &relation, souffle::SouffleProgram *prog)
{
    T result;
    for(auto &output : *prog->getRelation(relation))
    {
        result.contents.emplace_back(output);
    }
    result.sort();
    return result;
}

gtirb::Context C;

static gtirb::Symbol::StorageKind getSymbolType(uint64_t sectionIndex, std::string scope)
{
    if(sectionIndex == 0)
        return gtirb::Symbol::StorageKind::Undefined;
    if(scope == "GLOBAL")
        return gtirb::Symbol::StorageKind::Normal;
    if(scope == "LOCAL")
        return gtirb::Symbol::StorageKind::Local;
    return gtirb::Symbol::StorageKind::Extern;
}

static void buildSymbols(gtirb::Module &module, souffle::SouffleProgram *prog)
{
    for(auto &output : *prog->getRelation("symbol"))
    {
        assert(output.size() == 6);
        gtirb::Addr base;
        uint64_t size, sectionIndex;
        std::string type, scope, name;
        output >> base >> size >> type >> scope >> sectionIndex >> name;
        // Symbols with special section index do not have an address
        if(sectionIndex == static_cast<int>(LIEF::ELF::SYMBOL_SECTION_INDEX::SHN_UNDEF)
           || (sectionIndex >= static_cast<int>(LIEF::ELF::SYMBOL_SECTION_INDEX::SHN_LORESERVE)
               && sectionIndex <= static_cast<int>(LIEF::ELF::SYMBOL_SECTION_INDEX::SHN_HIRESERVE)))
            gtirb::emplaceSymbol(module, C, name);
        else
            gtirb::emplaceSymbol(module, C, base, name, getSymbolType(sectionIndex, scope));
    }
    for(auto &output : *prog->getRelation("inferred_symbol_name"))
    {
        gtirb::Addr addr;
        std::string name;
        output >> addr >> name;
        if(!module.findSymbols(name))
            gtirb::emplaceSymbol(module, C, addr, name);
    }
}

static void buildSections(gtirb::Module &module, std::shared_ptr<BinaryReader> binary,
                          souffle::SouffleProgram *prog)
{
    auto &byteMap = module.getImageByteMap();
    byteMap.setAddrMinMax(
        {gtirb::Addr(binary->get_min_address()), gtirb::Addr(binary->get_max_address())});
    std::map<gtirb::UUID, std::tuple<uint64_t, uint64_t>> sectionProperties;
    for(auto &output : *prog->getRelation("section_complete"))
    {
        assert(output.size() == 5);

        gtirb::Addr address;
        uint64_t size, type, flags;
        std::string name;
        output >> name >> size >> address >> type >> flags;
        if(flags & static_cast<int>(LIEF::ELF::ELF_SECTION_FLAGS::SHF_ALLOC)
           || binary->get_binary_format() == "PE")
        {
            gtirb::Section *section = gtirb::Section::Create(C, name, address, size);
            module.addSection(section);
            sectionProperties[section->getUUID()] = std::make_tuple(type, flags);
            if(auto sectionData = binary->get_section_content_and_address(name))
            {
                std::vector<uint8_t> &sectionBytes = std::get<0>(*sectionData);
                std::byte *begin = reinterpret_cast<std::byte *>(sectionBytes.data());
                std::byte *end =
                    reinterpret_cast<std::byte *>(sectionBytes.data() + sectionBytes.size());
                byteMap.setData(address, boost::make_iterator_range(begin, end));
            }
        }
    }
    module.addAuxData("elfSectionProperties", std::move(sectionProperties));
}

// auxiliary function to get a symbol with an address and name
static gtirb::Symbol *findSymbol(gtirb::Module &module, gtirb::Addr ea, std::string name)
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
static void buildSymbolForwarding(gtirb::Module &module, souffle::SouffleProgram *prog)
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
                gtirb::Symbol *realSymbol = gtirb::emplaceSymbol(module, C, name);
                gtirb::renameSymbol(module, *copySymbol, name + "_copy");
                symbolForwarding[copySymbol->getUUID()] = realSymbol->getUUID();
            }
        }
    }
    module.addAuxData("symbolForwarding", std::move(symbolForwarding));
}

// Expand the SymbolForwarding table with plt references
static void expandSymbolForwarding(gtirb::Module &module, souffle::SouffleProgram *prog)
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

static std::string getLabel(uint64_t ea)
{
    std::stringstream ss;
    ss << ".L_" << std::hex << ea;
    return ss.str();
}

static gtirb::Symbol *getSymbol(gtirb::Module &module, gtirb::Addr ea)
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
    auto *sym =
        gtirb::Symbol::Create(C, ea, getLabel(uint64_t(ea)), gtirb::Symbol::StorageKind::Local);
    module.addSymbol(sym);
    return sym;
}

void buildSymbolic(gtirb::Module &module, DecodedInstruction instruction, gtirb::Addr &ea,
                   uint64_t operand, uint64_t index, const SymbolicInfo &symbolicInfo,
                   const VectorByN<OpImmediate> &opImmediate,
                   const VectorByN<OpIndirect> &opIndirect)
{
    const auto foundImm = opImmediate.find(operand);
    if(foundImm != nullptr)
    {
        int64_t immediate = foundImm->Immediate;
        auto rangeMovedLabel = symbolicInfo.MovedLabels.equal_range(ea);
        if(auto movedLabel = std::find_if(rangeMovedLabel.first, rangeMovedLabel.second,
                                          [ea, index](const auto &element) {
                                              return (element.EA == ea) && (element.OpNum == index);
                                          });
           movedLabel != rangeMovedLabel.second)
        {
            assert(movedLabel->Offset1 == immediate);
            auto diff = movedLabel->Offset1 - movedLabel->Offset2;
            auto sym = getSymbol(module, gtirb::Addr(movedLabel->Offset2));
            module.addSymbolicExpression(ea + instruction.immediateOffset,
                                         gtirb::SymAddrConst{diff, sym});
            return;
        }

        auto range = symbolicInfo.SymbolicExpressions.equal_range(ea);
        if(std::find_if(range.first, range.second,
                        [ea, index](const auto &element) {
                            return (element.EA == ea) && (element.OpNum == index);
                        })
           != range.second)
        {
            auto sym = getSymbol(module, gtirb::Addr(immediate));
            module.addSymbolicExpression(ea + instruction.immediateOffset,
                                         gtirb::SymAddrConst{0, sym});
            return;
        }
    }

    const auto foundInd = opIndirect.find(operand);

    if(foundInd != nullptr)
    {
        auto op = *foundInd;

        auto rangeMovedLabel = symbolicInfo.MovedLabels.equal_range(ea);
        if(auto movedLabel = std::find_if(rangeMovedLabel.first, rangeMovedLabel.second,
                                          [ea, index](const auto &element) {
                                              return (element.EA == ea) && (element.OpNum == index);
                                          });
           movedLabel != rangeMovedLabel.second)
        {
            auto diff = movedLabel->Offset1 - movedLabel->Offset2;
            auto sym = getSymbol(module, gtirb::Addr(movedLabel->Offset2));
            module.addSymbolicExpression(ea + instruction.displacementOffset,
                                         gtirb::SymAddrConst{diff, sym});
            return;
        }

        auto range = symbolicInfo.SymbolicExpressions.equal_range(ea);
        if(std::find_if(range.first, range.second,
                        [ea, index](const auto &element) {
                            return (element.EA == ea) && (element.OpNum == index);
                        })
           != range.second)
        {
            if(op.Reg1 == std::string{"RIP"} && op.Multiplier == 1 && isNullReg(op.SReg)
               && isNullReg(op.Reg2))
            {
                auto address = ea + foundInd->Offset + instruction.Size;
                auto sym = getSymbol(module, address);
                module.addSymbolicExpression(ea + instruction.displacementOffset,
                                             gtirb::SymAddrConst{0, sym});
            }
            else
            {
                auto sym = getSymbol(module, gtirb::Addr(op.Offset));
                module.addSymbolicExpression(ea + instruction.displacementOffset,
                                             gtirb::SymAddrConst{0, sym});
            }
        }
    }
}

void buildCodeSymbolicInformation(gtirb::Module &module, souffle::SouffleProgram *prog)
{
    auto codeInBlock = convertRelation<CodeInBlock>("code_in_refined_block", prog);
    SymbolicInfo symbolicInfo{
        convertSortedRelation<VectorByEA<MovedLabel>>("moved_label", prog),
        convertSortedRelation<VectorByEA<SymbolicExpression>>("symbolic_operand", prog)};
    auto decodedInstructions =
        convertSortedRelation<VectorByEA<DecodedInstruction>>("instruction_complete", prog);
    auto opImmediate = convertSortedRelation<VectorByN<OpImmediate>>("op_immediate", prog);
    auto opIndirect = convertSortedRelation<VectorByN<OpIndirect>>("op_indirect", prog);
    for(auto &cib : codeInBlock)
    {
        const auto inst = decodedInstructions.find(cib.EA);
        assert(inst != nullptr);
        buildSymbolic(module, *inst, cib.EA, inst->Op1, 1, symbolicInfo, opImmediate, opIndirect);
        buildSymbolic(module, *inst, cib.EA, inst->Op2, 2, symbolicInfo, opImmediate, opIndirect);
        buildSymbolic(module, *inst, cib.EA, inst->Op3, 3, symbolicInfo, opImmediate, opIndirect);
        buildSymbolic(module, *inst, cib.EA, inst->Op4, 4, symbolicInfo, opImmediate, opIndirect);
    }
}

void buildCodeBlocks(gtirb::Module &module, souffle::SouffleProgram *prog)
{
    auto blockInformation =
        convertSortedRelation<VectorByEA<BlockInformation>>("block_information", prog);
    for(auto &output : *prog->getRelation("refined_block"))
    {
        gtirb::Addr blockAddress;
        output >> blockAddress;
        uint64_t size = blockInformation.find(blockAddress)->size;
        emplaceBlock(module, C, blockAddress, size);
    }
}

// Create DataObjects for labeled objects in the BSS sections, without adding
// data to the ImageByteMap.

void buildBSS(gtirb::Module &module, souffle::SouffleProgram *prog)
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
            auto *d = gtirb::DataObject::Create(C, *i, *next - *i);
            module.addData(d);
        }
    }
}

void buildDataGroups(gtirb::Module &module, std::shared_ptr<BinaryReader> binary,
                     souffle::SouffleProgram *prog)
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
    std::map<gtirb::UUID, std::string> typesTable;

    for(auto &section : binary->get_non_zero_data_sections())
    {
        auto foundSection = module.findSection(section.name);
        if(foundSection != module.section_by_name_end())
        {
            gtirb::Section &s = *foundSection;
            auto limit = addressLimit(s);
            for(auto currentAddr = s.getAddress(); currentAddr < limit; currentAddr++)
            {
                // undefined symbol
                const auto symbolicExpr = symbolicExprs.find(currentAddr);
                if(symbolicExpr != nullptr)
                {
                    auto *d = gtirb::DataObject::Create(C, currentAddr, symbolicExpr->Size);
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
                if(movedDataLabel != nullptr)
                {
                    auto *d = gtirb::DataObject::Create(C, currentAddr, movedDataLabel->Size);
                    module.addData(d);
                    auto diff = movedDataLabel->Offset1 - movedDataLabel->Offset2;
                    auto sym = getSymbol(module, gtirb::Addr(movedDataLabel->Offset2));
                    module.addSymbolicExpression(currentAddr, gtirb::SymAddrConst{diff, sym});
                    const auto specialType = symbolSpecialTypes.find(currentAddr);
                    if(specialType != nullptr)
                        typesTable[d->getUUID()] = specialType->Type;
                    currentAddr += (movedDataLabel->Size) - 1;
                    continue;
                }
                // symbol+0
                const auto symbolic = symbolicData.find(currentAddr);
                if(symbolic != nullptr)
                {
                    auto *d = gtirb::DataObject::Create(C, currentAddr, symbolic->Size);
                    module.addData(d);
                    auto sym = getSymbol(module, symbolic->GroupContent);
                    module.addSymbolicExpression(currentAddr, gtirb::SymAddrConst{0, sym});
                    const auto specialType = symbolSpecialTypes.find(currentAddr);
                    if(specialType != nullptr)
                        typesTable[d->getUUID()] = specialType->Type;
                    currentAddr += (symbolic->Size - 1);
                    continue;
                }
                // symbol-symbol
                const auto symMinusSym = symbolMinusSymbol.find(currentAddr);
                if(symMinusSym != nullptr)
                {
                    auto *d = gtirb::DataObject::Create(C, currentAddr, symMinusSym->Size);
                    module.addData(d);
                    module.addSymbolicExpression(
                        gtirb::Addr(currentAddr),
                        gtirb::SymAddrAddr{1, 0, getSymbol(module, symMinusSym->Symbol2),
                                           getSymbol(module, symMinusSym->Symbol1)});
                    const auto specialType = symbolSpecialTypes.find(currentAddr);
                    if(specialType != nullptr)
                        typesTable[d->getUUID()] = specialType->Type;
                    currentAddr += (symMinusSym->Size - 1);
                    continue;
                }
                // string
                const auto str = dataStrings.find(currentAddr);
                if(str != nullptr)
                {
                    auto *d = gtirb::DataObject::Create(C, currentAddr, str->End - currentAddr);
                    module.addData(d);
                    typesTable[d->getUUID()] = std::string{"string"};

                    // Because the loop is going to increment this counter, don't skip a byte.
                    currentAddr = str->End - 1;
                    continue;
                }
                // Store raw data
                auto *d = gtirb::DataObject::Create(C, currentAddr, 1);
                module.addData(d);
            }
        }
    }
    buildBSS(module, prog);
    module.addAuxData("encodings", std::move(typesTable));
}

static void connectSymbolsToDataGroups(gtirb::Module &module)
{
    std::for_each(module.data_begin(), module.data_end(), [&module](auto &d) {
        auto found = module.findSymbols(d.getAddress());
        std::for_each(found.begin(), found.end(),
                      [&d, &module](auto &sym) { gtirb::setReferent(module, sym, &d); });
    });
}

static void connectSymbolsToBlocks(gtirb::Module &module)
{
    auto &cfg = module.getCFG();
    for(auto &block : blocks(cfg))
    {
        for(auto &symbol : module.findSymbols(block.getAddress()))
            gtirb::setReferent(module, symbol, &block);
    }
}

static void buildFunctions(gtirb::Module &module, souffle::SouffleProgram *prog)
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

static gtirb::EdgeType getEdgeType(const std::string &type)
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

static void buildCFG(gtirb::Module &module, souffle::SouffleProgram *prog)
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
    auto *topBlock = gtirb::ProxyBlock::Create(C);
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
            externalBlock = gtirb::ProxyBlock::Create(C);
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
static std::vector<gtirb::Offset> findOffsets(gtirb::Module &module, gtirb::Addr ea)
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

static void updateComment(gtirb::Module &module, std::map<gtirb::Offset, std::string> &comments,
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

static void buildCfiDirectives(gtirb::Module &module, souffle::SouffleProgram *prog)
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
                gtirb::Symbol *symbol = getSymbol(module, reference);
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

static void buildComments(gtirb::Module &module, souffle::SouffleProgram *prog, bool selfDiagnose)
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

    for(auto &output : *prog->getRelation("data_directory"))
    {
        gtirb::Addr ea;
        uint64_t size;
        std::string type;
        output >> ea >> size >> type;
        std::ostringstream newComment;
        newComment << "data_directory:" << type;
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

static void buildIR(gtirb::IR &ir, const std::string &filename,
                    std::shared_ptr<BinaryReader> binary, souffle::SouffleProgram *prog,
                    bool selfDiagnose)
{
    gtirb::Module &module = *gtirb::Module::Create(C);
    module.setBinaryPath(filename);
    module.setFileFormat(gtirb::FileFormat::ELF);
    module.setISAID(gtirb::ISAID::X64);
    ir.addModule(&module);
    buildSymbols(module, prog);
    buildSymbolForwarding(module, prog);
    buildSections(module, binary, prog);
    buildDataGroups(module, binary, prog);
    buildCodeBlocks(module, prog);
    buildCodeSymbolicInformation(module, prog);
    connectSymbolsToDataGroups(module);
    buildCfiDirectives(module, prog);
    expandSymbolForwarding(module, prog);
    connectSymbolsToBlocks(module);
    buildFunctions(module, prog);
    buildCFG(module, prog);
    buildComments(module, prog, selfDiagnose);
    module.addAuxData("libraries", binary->get_libraries());
    module.addAuxData("libraryPaths", binary->get_library_paths());
}

static void performSanityChecks(souffle::SouffleProgram *prog, bool selfDiagnose)
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

static void decode(Dl_decoder &decoder, std::shared_ptr<BinaryReader> binary)
{
    for(const auto &codeSection : binary->get_code_sections())
    {
        if(auto section = binary->get_section_content_and_address(codeSection.name))
        {
            decoder.decode_section(std::get<0>(*section).data(), std::get<0>(*section).size(),
                                   std::get<1>(*section));
        }
    }
    uint64_t min_address = binary->get_min_address();
    uint64_t max_address = binary->get_max_address();
    for(const auto &dataSection : binary->get_non_zero_data_sections())
    {
        if(auto section = binary->get_section_content_and_address(dataSection.name))
        {
            decoder.store_data_section(std::get<0>(*section).data(), std::get<0>(*section).size(),
                                       std::get<1>(*section), min_address, max_address);
        }
    }
}

static void writeFacts(souffle::SouffleProgram *prog, const std::string &directory)
{
    std::ios_base::openmode filemask = std::ios::out;
    for(souffle::Relation *relation : prog->getInputRelations())
    {
        std::ofstream file(directory + relation->getName() + ".facts", filemask);
        souffle::SymbolTable symbolTable = relation->getSymbolTable();
        for(souffle::tuple tuple : *relation)
        {
            for(size_t i = 0; i < tuple.size(); i++)
            {
                if(i > 0)
                    file << "\t";
                if(relation->getAttrType(i)[0] == 's')
                    file << symbolTable.resolve(tuple[i]);
                else
                    file << tuple[i];
            }
            file << std::endl;
        }
        file.close();
    }
}

souffle::tuple &operator<<(souffle::tuple &t, const Dl_instruction &inst)
{
    t << inst.address << inst.size << inst.prefix << inst.name;
    for(size_t i = 0; i < 4; ++i)
    {
        if(i < inst.op_codes.size())
            t << inst.op_codes[i];
        else
            t << 0;
    }
    t << inst.immediateOffset << inst.displacementOffset;
    return t;
}

template <class T>
souffle::tuple &operator<<(souffle::tuple &t, const Dl_data<T> &data)
{
    t << data.ea << static_cast<int64_t>(data.content);
    return t;
}

souffle::tuple &operator<<(souffle::tuple &t, const std::pair<Dl_operator, int64_t> &pair)
{
    auto &[op, id] = pair;
    switch(op.type)
    {
        case NONE:
        default:
            break;
        case REG:
            t << id << op.reg1;
            break;
        case IMMEDIATE:
            t << id << op.offset;
            break;
        case INDIRECT:
            t << id << op.reg1 << op.reg2 << op.reg3 << op.multiplier << op.offset << op.size;
            break;
    }

    return t;
}

souffle::tuple &operator<<(souffle::tuple &t, const Section &section)
{
    t << section.name << section.size << section.address << section.type << section.flags;
    return t;
}

souffle::tuple &operator<<(souffle::tuple &t, const Symbol &symbol)
{
    t << symbol.address << symbol.size << symbol.type << symbol.scope << symbol.sectionIndex
      << symbol.name;
    return t;
}

souffle::tuple &operator<<(souffle::tuple &t, const Relocation &relocation)
{
    t << relocation.address << relocation.type << relocation.name << relocation.addend;
    return t;
}

souffle::tuple &operator<<(souffle::tuple &t, const DataDirectory &directory)
{
    t << directory.address << directory.size << directory.type;
    return t;
}

souffle::tuple &operator<<(souffle::tuple &t, const ImportEntry &iEntry)
{
    t << iEntry.iat_address << iEntry.ordinal << iEntry.function << iEntry.library;
    return t;
}

template <typename T>
void addRelation(souffle::SouffleProgram *prog, const std::string &name, const std::vector<T> &data)
{
    auto *rel = prog->getRelation(name);
    for(const auto elt : data)
    {
        souffle::tuple t(rel);
        t << elt;
        rel->insert(t);
    }
}

static void loadInputs(souffle::SouffleProgram *prog, std::shared_ptr<BinaryReader> binary,
                       const Dl_decoder &decoder)
{
    addRelation<std::string>(prog, "binary_type", {binary->get_binary_type()});
    addRelation<std::string>(prog, "binary_format", {binary->get_binary_format()});
    addRelation<uint64_t>(prog, "entry_point", {binary->get_entry_point()});
    addRelation(prog, "section_complete", binary->get_sections());
    addRelation(prog, "symbol", binary->get_symbols());
    addRelation(prog, "relocation", binary->get_relocations());
    addRelation(prog, "data_directory", binary->get_data_directories());
    addRelation(prog, "import_entry", binary->get_import_entries());
    addRelation(prog, "instruction_complete", decoder.instructions);
    addRelation(prog, "address_in_data", decoder.data_addresses);
    addRelation(prog, "data_byte", decoder.data_bytes);
    addRelation(prog, "invalid_op_code", decoder.invalids);
    addRelation(prog, "op_regdirect", decoder.op_dict.get_operators_of_type(operator_type::REG));
    addRelation(prog, "op_immediate",
                decoder.op_dict.get_operators_of_type(operator_type::IMMEDIATE));
    addRelation(prog, "op_indirect",
                decoder.op_dict.get_operators_of_type(operator_type::INDIRECT));

    ExceptionDecoder excDecoder(binary);
    excDecoder.addExceptionInformation(prog);
}

namespace std
{
    // program_options default values need to be printable.
    std::ostream &operator<<(std::ostream &os, const std::vector<std::string> &vec)
    {
        for(auto item : vec)
        {
            os << item << ",";
        }
        return os;
    }
} // namespace std

using namespace boost;
namespace po = boost::program_options;
using namespace std;

int main(int argc, char **argv)
{
    po::options_description desc("Allowed options");
    desc.add_options()                                                  //
        ("help", "produce help message")                                //
        ("ir", po::value<std::string>(), "GTIRB output file")           //
        ("json", po::value<std::string>(), "GTIRB json output file")    //
        ("asm", po::value<std::string>(), "ASM output file")            //
        ("debug", "generate assembler file with debugging information") //
        ("debug-dir", po::value<std::string>(),                         //
         "location to write CSV files for debugging")                   //
        ("input-file", po::value<std::string>(), "file to disasemble")(
            "keep-functions,K",
            boost::program_options::value<std::vector<std::string>>()->multitoken(),
            "Print the given functions even if they are skipped by default (e.g. _start)")(
            "self-diagnose",
            "Use relocation information to emit a self diagnose of the symbolization process. This "
            "option only works if the target binary contains complete relocation information.");
    po::positional_options_description pd;
    pd.add("input-file", -1);

    po::variables_map vm;
    try
    {
        po::store(po::command_line_parser(argc, argv).options(desc).positional(pd).run(), vm);

        if(vm.count("help"))
        {
            std::cout << "Usage: " << argv[0] << " [OPTIONS...] INPUT_FILE\n"
                      << "Disassemble INPUT_FILE and output assembly code and/or gtirb.\n\n"
                      << desc << "\n";
            return 1;
        }
        po::notify(vm);
    }
    catch(std::exception &e)
    {
        std::cerr << "Error: " << e.what() << "\nTry '" << argv[0]
                  << " --help' for more information.\n";
        return 1;
    }

    if(vm.count("input-file") < 1)
    {
        std::cerr << "Error: missing input file\nTry '" << argv[0]
                  << " --help' for more information.\n";
        return 1;
    }

    std::string filename = vm["input-file"].as<std::string>();
    std::shared_ptr<BinaryReader> binary(new LIEFBinaryReader(filename));
    if(!binary->is_valid())
    {
        std::cerr << "There was a problem loading the binary file " << filename << "\n";
        return 1;
    }
    Dl_decoder decoder;
    decode(decoder, binary);
    std::cout << "Decoding the binary" << std::endl;
    if(souffle::SouffleProgram *prog = souffle::ProgramFactory::newInstance("souffle_disasm"))
    {
        try
        {
            loadInputs(prog, binary, decoder);
            std::cout << "Disassembling" << std::endl;
            prog->run();

            std::cout << "Building the gtirb representation" << std::endl;
            auto &ir = *gtirb::IR::Create(C);
            buildIR(ir, filename, binary, prog, vm.count("self-diagnose") != 0);

            // Output GTIRB
            if(vm.count("ir") != 0)
            {
                std::ofstream out(vm["ir"].as<std::string>());
                ir.save(out);
            }
            // Output json GTIRB
            if(vm.count("json") != 0)
            {
                std::ofstream out(vm["json"].as<std::string>());
                ir.saveJSON(out);
            }
            // Pretty-print
            gtirb_pprint::PrettyPrinter pprinter;
            pprinter.setDebug(vm.count("debug"));
            if(vm.count("keep-functions") != 0)
            {
                for(auto keep : vm["keep-functions"].as<std::vector<std::string>>())
                {
                    pprinter.keepFunction(keep);
                }
            }
            if(vm.count("asm") != 0)
            {
                std::cout << "Printing assembler" << std::endl;
                std::ofstream out(vm["asm"].as<std::string>());
                pprinter.print(out, C, ir);
            }
            else if(vm.count("ir") == 0)
            {
                std::cout << "Printing assembler" << std::endl;
                pprinter.print(std::cout, C, ir);
            }

            if(vm.count("debug-dir") != 0)
            {
                std::cout << "Writing facts to debug dir " << vm["debug-dir"].as<std::string>()
                          << std::endl;
                auto dir = vm["debug-dir"].as<std::string>() + "/";
                writeFacts(prog, dir);
                prog->printAll(dir);
            }
            performSanityChecks(prog, vm.count("self-diagnose") != 0);
            delete prog;
            return 0;
        }
        catch(std::exception &e)
        {
            souffle::SignalHandler::instance()->error(e.what());
        }
    }
    else
    {
        std::cerr << "Failed to create instance for program <name>\n";
        return 1;
    }

    return 0;
}
