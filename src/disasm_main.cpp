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
#include <fstream>
#include <gtirb/gtirb.hpp>
#include <iostream>
#include <string>
#include <utility>
#include <vector>
#include "Dl_decoder.h"
#include "Elf_reader.h"

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
        assert(tuple.size() == 8);

        std::string prefix, opcode;

        tuple >> EA >> Size >> prefix >> opcode;
        // Need to identify rets for the CFG, otherwise prefix and opcode can
        // be ignored
        this->isRet = (opcode == "RET");
        this->Op1 = tuple[4];
        this->Op2 = tuple[5];
        this->Op3 = tuple[6];
        this->Op4 = tuple[7];
    };

    gtirb::Addr EA{0};
    uint64_t Size{0};
    uint64_t Op1{0};
    uint64_t Op2{0};
    uint64_t Op3{0};
    uint64_t Op4{0};
    bool isRet{false};
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

struct AddrPair
{
    AddrPair(souffle::tuple &tuple)
    {
        assert(tuple.size() == 2);

        tuple >> Addr1 >> Addr2;
    };

    gtirb::Addr Addr1{0};
    gtirb::Addr Addr2{0};
};

struct DirectCall
{
    DirectCall(gtirb::Addr ea) : EA(ea)
    {
    }

    DirectCall(souffle::tuple &tuple)
    {
        assert(tuple.size() == 2);

        tuple >> EA >> Destination;
    };

    gtirb::Addr EA{0};
    gtirb::Addr Destination{0};
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
        assert(tuple.size() == 3);
        tuple >> EA >> Offset1 >> Offset2;
    };

    gtirb::Addr EA{0};
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
        assert(tuple.size() == 2);
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
    VectorByEA<PLTReference> PLTCodeReferences;
    VectorByEA<DirectCall> DirectCalls;
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
        assert(tuple.size() == 2);
        tuple >> EA >> GroupContent;
    };

    gtirb::Addr EA{0};
    uint64_t GroupContent{0};
};

struct SymbolMinusSymbol
{
    SymbolMinusSymbol(gtirb::Addr ea) : EA(ea)
    {
    }

    SymbolMinusSymbol(souffle::tuple &tuple)
    {
        assert(tuple.size() == 3);

        tuple >> EA >> Symbol1 >> Symbol2;
    };

    gtirb::Addr EA{0};
    gtirb::Addr Symbol1{0};
    gtirb::Addr Symbol2{0};
};

// "String" is a bad name for this data type.
struct String
{
    String(gtirb::Addr ea) : EA(ea)
    {
    }

    String(souffle::tuple &tuple)
    {
        assert(tuple.size() == 2);

        tuple >> EA >> End;
    };

    gtirb::Addr EA{0};
    gtirb::Addr End{0};
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

static std::map<gtirb::Addr, uint64_t> buildSymbols(gtirb::IR &ir, souffle::SouffleProgram *prog)
{
    std::map<gtirb::Addr, uint64_t> symbolSizes;
    auto &module = ir.modules()[0];
    std::vector<gtirb::Addr> functionEAs;

    for(auto &output : *prog->getRelation("symbol"))
    {
        assert(output.size() == 5);

        gtirb::Addr base;
        uint64_t size;
        std::string type, scope, name;

        output >> base >> size >> type >> scope >> name;

        symbolSizes[base] = size;
        // NOTE: don't seem to care about OBJECT or NOTYPE, and not clear how
        // to represent them in gtirb.
        if(type == "FUNC")
        {
            functionEAs.push_back(base);
        }
        // FIXME: Skip symbols with no type or with object type and zero size
        // This is to avoid conflics when building symbolic expressions (several symbols with same
        // address)
        if(type != "NOTYPE" && (type != "OBJECT" || size > 0))
            module.addSymbol(gtirb::Symbol::Create(C, base, name,
                                                   scope == "GLOBAL"
                                                       ? gtirb::Symbol::StorageKind::Extern
                                                       : gtirb::Symbol::StorageKind::Local));
    }

    std::sort(functionEAs.begin(), functionEAs.end());
    ir.addAuxData("functionEAs", std::move(functionEAs));

    if(!module.findSymbols("main"))
        for(gtirb::Addr addrMain: convertRelation<gtirb::Addr>("main_function", prog))
            module.addSymbol(gtirb::Symbol::Create(C,addrMain,"main"));
    if(!module.findSymbols("_start"))
        for(gtirb::Addr addrMain: convertRelation<gtirb::Addr>("start_function", prog))
            module.addSymbol(gtirb::Symbol::Create(C,addrMain,"_start"));
    return symbolSizes;
}

static void buildSections(gtirb::IR &ir, Elf_reader &elf, souffle::SouffleProgram *prog)
{
    auto &byteMap = ir.modules()[0].getImageByteMap();
    byteMap.setAddrMinMax({gtirb::Addr(elf.get_min_address()), gtirb::Addr(elf.get_max_address())});

    auto &module = ir.modules()[0];
    for(auto &output : *prog->getRelation("section"))
    {
        assert(output.size() == 3);

        gtirb::Addr address;
        uint64_t size;
        std::string name;
        output >> name >> size >> address;
        module.addSection(gtirb::Section::Create(C, name, address, size));

        // Copy section data into the byteMap. There seem to be some
        // overlapping sections at address 0 which cause problems, so ignore
        // them for now.
        if(address != gtirb::Addr(0))
        {
            int64_t size2;
            uint64_t address2;
            char *buf = elf.get_section(name, size2, address2);
            // FIXME: why does the ELF reader sometimes have different
            // sections than the souffle relations?
            if(buf != nullptr)
            {
                byteMap.setData(address, as_bytes(gsl::make_span(buf, size)));
            }
        }
    }
}

static void buildRelocations(gtirb::IR &ir, souffle::SouffleProgram *prog)
{
    std::map<gtirb::Addr, std::tuple<std::string, std::string>> relocations;
    for(auto &output : *prog->getRelation("relocation"))
    {
        gtirb::Addr ea;
        uint64_t offset;
        std::string type, name;
        output >> ea >> type >> name >> offset;
        // Datalog code turns empty string in "n/a" somewhere. Put it back.
        if(name == "n/a")
            name.clear();
        relocations[ea] = {type, name};
    }
    ir.addAuxData("relocations", std::move(relocations));
}

bool isNullReg(const std::string &reg)
{
    const std::vector<std::string> adapt{"NullReg64", "NullReg32", "NullReg16", "NullSReg"};

    const auto found = std::find(std::begin(adapt), std::end(adapt), reg);
    return (found != std::end(adapt));
}

static std::string getLabel(uint64_t ea)
{
    std::stringstream ss;
    ss << ".L_" << std::hex << ea;
    return ss.str();
}

static gtirb::Symbol *getSymbol(gtirb::Module &module, gtirb::Addr ea)
{
    auto found = module.findSymbols(ea);
    if(!found.empty())
    {
        return &*found.begin();
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
    // FIXME: we're faking the operand offset here, assuming it's equal
    // to index. This works as long as the pretty-printer does the same
    // thing, but it isn't right.
    const auto foundImm = opImmediate.find(operand);

    if(foundImm != nullptr)
    {
        int64_t immediate = foundImm->Immediate;

        auto pltReference = symbolicInfo.PLTCodeReferences.find(ea);
        if(pltReference != nullptr)
        {
            auto sym = getSymbol(module, gtirb::Addr(immediate));
            module.addSymbolicExpression(ea + index, gtirb::SymAddrConst{0, sym});
        }

        auto directCall = symbolicInfo.DirectCalls.find(ea);
        if(directCall != nullptr)
        {
            auto sym = getSymbol(module, directCall->Destination);
            module.addSymbolicExpression(ea + index, gtirb::SymAddrConst{0, sym});
        }

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
            module.addSymbolicExpression(ea + index, gtirb::SymAddrConst{diff, sym});
        }

        auto range = symbolicInfo.SymbolicExpressions.equal_range(ea);
        if(std::find_if(range.first, range.second,
                        [ea, index](const auto &element) {
                            return (element.EA == ea) && (element.OpNum == index);
                        })
           != range.second)
        {
            auto sym = getSymbol(module, gtirb::Addr(immediate));
            module.addSymbolicExpression(ea + index, gtirb::SymAddrConst{0, sym});
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
            module.addSymbolicExpression(ea + index, gtirb::SymAddrConst{diff, sym});
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
                module.addSymbolicExpression(ea + index, gtirb::SymAddrConst{0, sym});
            }
            else
            {
                auto sym = getSymbol(module, gtirb::Addr(op.Offset));
                module.addSymbolicExpression(ea + index, gtirb::SymAddrConst{0, sym});
            }
        }
    }
}

void buildCodeBlocks(gtirb::IR &ir, souffle::SouffleProgram *prog)
{
    auto codeInBlock = convertRelation<CodeInBlock>("code_in_refined_block", prog);

    SymbolicInfo symbolicInfo{
        convertSortedRelation<VectorByEA<PLTReference>>("plt_code_reference", prog),
        convertSortedRelation<VectorByEA<DirectCall>>("direct_call", prog),
        convertSortedRelation<VectorByEA<MovedLabel>>("moved_label", prog),
        convertSortedRelation<VectorByEA<SymbolicExpression>>("symbolic_operand", prog)};
    auto decodedInstructions =
        convertSortedRelation<VectorByEA<DecodedInstruction>>("instruction", prog);
    auto opImmediate = convertSortedRelation<VectorByN<OpImmediate>>("op_immediate", prog);
    auto opIndirect = convertSortedRelation<VectorByN<OpIndirect>>("op_indirect", prog);

    auto &module = ir.modules()[0];
    auto &cfg = module.getCFG();
    std::map<gtirb::Addr, gtirb::Addr> blockCalls;

    for(auto &output : *prog->getRelation("refined_block"))
    {
        gtirb::Addr blockAddress;
        output >> blockAddress;
        std::vector<gtirb::Addr> instructions;
        bool hasRet = false;
        bool hasCall = false;

        for(auto &cib : codeInBlock)
        {
            if(cib.BlockAddress == blockAddress)
            {
                const auto inst = decodedInstructions.find(cib.EA);
                assert(inst != nullptr);

                instructions.emplace_back(cib.EA);
                buildSymbolic(module, *inst, cib.EA, inst->Op1, 1, symbolicInfo, opImmediate,
                              opIndirect);
                buildSymbolic(module, *inst, cib.EA, inst->Op2, 2, symbolicInfo, opImmediate,
                              opIndirect);
                buildSymbolic(module, *inst, cib.EA, inst->Op3, 3, symbolicInfo, opImmediate,
                              opIndirect);
                buildSymbolic(module, *inst, cib.EA, inst->Op4, 4, symbolicInfo, opImmediate,
                              opIndirect);
                if(inst->isRet)
                {
                    hasRet = true;
                }
                if(auto *call = symbolicInfo.DirectCalls.find(cib.EA))
                {
                    hasCall = true;
                    blockCalls.emplace(cib.BlockAddress, call->Destination);
                }
            }
        }

        std::sort(instructions.begin(), instructions.end());

        uint64_t size;
        if(!instructions.empty())
        {
            auto address = instructions.back();
            const auto inst = decodedInstructions.find(address);
            assert(inst != nullptr);

            size = address + inst->Size - blockAddress;
        }
        else
        {
            size = 0;
        }

        gtirb::Block::Exit exit;
        if(hasRet)
        {
            exit = gtirb::Block::Exit::Return;
        }
        else if(hasCall)
        {
            exit = gtirb::Block::Exit::Call;
        }
        else
        {
            exit = gtirb::Block::Exit::Fallthrough;
        }
        emplaceBlock(cfg, C, blockAddress, size, exit);
    }
    ir.addAuxData("blockCalls", std::move(blockCalls));

    std::map<gtirb::Addr, std::string> pltReferences;
    for(const auto &p : symbolicInfo.PLTCodeReferences.contents)
    {
        pltReferences[gtirb::Addr(p.EA)] = p.Name;
    }
    ir.addAuxData("pltCodeReferences", std::move(pltReferences));
}

// Create DataObjects for labeled objects in the BSS section, without adding
// data to the ImageByteMap.
void buildBSS(gtirb::IR &ir, souffle::SouffleProgram *prog,
              const std::map<gtirb::Addr, uint64_t> &symbolSizes)
{
    auto bssData = convertRelation<gtirb::Addr>("bss_data", prog);
    std::vector<gtirb::UUID> dataUUIDs;

    auto &module = ir.modules()[0];
    const auto &sections = module.sections();
    const auto found = std::find_if(sections.begin(), sections.end(), [](const auto &element) {
        return element.getName() == ".bss";
    });
    if(found == sections.end()){
        std::cerr << "Section .bss not found\n";
        return;
    }
    for(size_t i = 0; i < bssData.size(); ++i)
    {
        const gtirb::Addr current = bssData[i];

        if(i != bssData.size() - 1)
        {
            gtirb::Addr next = bssData[i + 1];

            // If there's a symbol at this location, adjust DataObject to
            // match symbol size.
            auto symbol = symbolSizes.find(current);
            if(symbol != symbolSizes.end() && symbol->second != 0)
            {
                uint64_t size = symbol->second;
                gtirb::Addr end = current + size;
                {
                    auto *d = gtirb::DataObject::Create(C, current, size);
                    module.addData(d);
                    dataUUIDs.push_back(d->getUUID());
                }

                // If symbol size was smaller than BSS object, fill in the
                // difference
                if(end < next)
                {
                    auto *d = gtirb::DataObject::Create(C, end, next - end);
                    module.addData(d);
                    dataUUIDs.push_back(d->getUUID());
                }
                // Otherwise, skip BSS objects contained within the symbol.
                else
                {
                    while(next < end && i < bssData.size() - 1)
                    {
                        i++;
                        next = bssData[i + 1];
                    }
                }
            }
            else
            {
                auto *d = gtirb::DataObject::Create(C, gtirb::Addr(current), next - current);
                module.addData(d);
                dataUUIDs.push_back(d->getUUID());
            }
        }
        else
        {
            // Continue to the end of the section.
            auto *d =
                gtirb::DataObject::Create(C, gtirb::Addr(current), addressLimit(*found) - current);
            module.addData(d);
            dataUUIDs.push_back(d->getUUID());
        }
    }

    ir.addAuxData("bssData", dataUUIDs);
}

void buildDataGroups(gtirb::IR &ir, souffle::SouffleProgram *prog,
                     const std::map<gtirb::Addr, uint64_t> &symbolSizes)
{
    std::vector<uint64_t> labeledData;
    for(auto &output : *prog->getRelation("labeled_data"))
    {
        uint64_t x;
        output >> x;
        labeledData.push_back(x);
    }

    auto symbolicData = convertSortedRelation<VectorByEA<SymbolicData>>("symbolic_data", prog);
    auto pltDataReference =
        convertSortedRelation<VectorByEA<PLTReference>>("plt_data_reference", prog);
    auto movedDataLabels =
        convertSortedRelation<VectorByEA<MovedDataLabel>>("moved_data_label", prog);
    auto symbolMinusSymbol =
        convertSortedRelation<VectorByEA<SymbolMinusSymbol>>("symbol_minus_symbol", prog);
    auto dataStrings = convertSortedRelation<VectorByEA<String>>("string", prog);
    auto &module = ir.modules()[0];

    std::vector<std::tuple<std::string, int, std::vector<gtirb::UUID>>> dataSections;
    std::vector<gtirb::Addr> stringEAs;

    for(auto &s : module.sections())
    {
        auto foundDataSection = getDataSectionDescriptor(s.getName());

        if(foundDataSection != nullptr)
        {
            std::vector<gtirb::UUID> dataGroupIds;

            auto limit = addressLimit(s);
            for(auto currentAddr = s.getAddress(); currentAddr < limit; currentAddr++)
            {
                // symbol+constant and symbol+0
                const auto symbolic = symbolicData.find(currentAddr);
                if(symbolic != nullptr)
                {
                    auto *d = gtirb::DataObject::Create(C, currentAddr, 8);
                    module.addData(d);
                    dataGroupIds.push_back(d->getUUID());

                    // if there is a moved_data_label we have a symbol+constant
                    int64_t diff = 0;
                    gtirb::Symbol *sym;
                    const auto movedDataLabel = movedDataLabels.find(currentAddr);
                    if(movedDataLabel != nullptr)
                    {
                        diff = movedDataLabel->Offset1 - movedDataLabel->Offset2;
                        sym = getSymbol(module, gtirb::Addr(movedDataLabel->Offset2));
                    }
                    else
                    {
                        sym = getSymbol(module, gtirb::Addr(symbolic->GroupContent));
                    }
                    module.addSymbolicExpression(currentAddr, gtirb::SymAddrConst{diff, sym});

                    currentAddr += 7;
                    continue;
                }

                // symbol-symbol
                const auto symMinusSym = symbolMinusSymbol.find(currentAddr);
                if(symMinusSym != nullptr)
                {
                    auto *d = gtirb::DataObject::Create(C, currentAddr, 4);
                    module.addData(d);
                    dataGroupIds.push_back(d->getUUID());

                    module.addSymbolicExpression(
                        gtirb::Addr(currentAddr),
                        gtirb::SymAddrAddr{1, 0, getSymbol(module, symMinusSym->Symbol2),
                                           getSymbol(module, symMinusSym->Symbol1)});

                    currentAddr += 3;
                    continue;
                }

                // string
                const auto str = dataStrings.find(currentAddr);
                if(str != nullptr)
                {
                    stringEAs.push_back(currentAddr);
                    auto *d = gtirb::DataObject::Create(C, currentAddr, str->End - currentAddr);
                    module.addData(d);
                    dataGroupIds.push_back(d->getUUID());

                    // Because the loop is going to increment this counter, don't skip a byte.
                    currentAddr = str->End - 1;

                    continue;
                }

                // Store raw data
                auto *d = gtirb::DataObject::Create(C, currentAddr, 1);
                module.addData(d);
                dataGroupIds.push_back(d->getUUID());
            }

            dataSections.emplace_back(s.getName(), foundDataSection->second, dataGroupIds);
        }
    }

    buildBSS(ir, prog, symbolSizes);

    ir.addAuxData("dataSections", std::move(dataSections));
    ir.addAuxData("stringEAs", std::move(stringEAs));

    std::map<gtirb::Addr, std::string> pltReferences;
    for(const auto &p : pltDataReference.contents)
    {
        pltReferences[gtirb::Addr(p.EA)] = p.Name;
    }
    ir.addAuxData("pltDataReferences", std::move(pltReferences));

    // Set referents of all symbols pointing to data
    std::for_each(module.data_begin(), module.data_end(), [&module](auto &d) {
        auto found = module.findSymbols(d.getAddress());
        std::for_each(found.begin(), found.end(), [&d](auto &sym) { sym.setReferent(&d); });
    });
}

static void buildFunctions(gtirb::IR &ir, souffle::SouffleProgram *prog)
{
    ir.addAuxData("functionEntry", convertRelation<gtirb::Addr>("function_entry2", prog));
}

static void buildCFG(gtirb::IR &ir, souffle::SouffleProgram *prog)
{
    // FIXME: this is missing some labels, and some cases for Block.Exit.
    // Most of the logic should be moved into datalog code and the remaining
    // details added there.
    auto &cfg = ir.modules()[0].getCFG();
    std::map<gtirb::Addr, const gtirb::Block *> blocksByEA;
    std::set<const gtirb::Block *> blocksWithRet;
    for(const auto &b : blocks(cfg))
    {
        blocksByEA.emplace(b.getAddress(), &b);
        if(b.getExitKind() == gtirb::Block::Exit::Return)
        {
            blocksWithRet.insert(&b);
        }
    }

    std::map<const gtirb::Block *, const gtirb::Block *> blockCalls;
    const auto &t2 = *ir.getAuxData("blockCalls")->get<std::map<gtirb::Addr, gtirb::Addr>>();
    std::transform(t2.begin(), t2.end(), std::inserter(blockCalls, blockCalls.begin()),
                   [&blocksByEA](const auto &elt) {
                       return std::make_pair(blocksByEA.find(elt.first)->second,
                                             blocksByEA.find(elt.second)->second);
                   });

    std::map<const gtirb::Block *, std::vector<const gtirb::Block *>> functionReturns;
    for(const auto &f : convertRelation<AddrPair>("in_function", prog))
    {
        if(auto b = blocksByEA.find(f.Addr1); b != blocksByEA.end())
        {
            auto block = blocksWithRet.find(b->second);
            auto fun = blocksByEA.find(f.Addr2);
            if(block != blocksWithRet.end() && fun != blocksByEA.end())
            {
                functionReturns[fun->second].push_back(*block);
            }
        }
    }

    for(const auto &edge : convertRelation<DirectCall>("intra_edge", prog))
    {
        if(auto fromI = blocksByEA.find(edge.EA), toI = blocksByEA.find(edge.Destination);
           fromI != blocksByEA.end() && toI != blocksByEA.end())
        {
            const gtirb::Block *from = fromI->second, *to = toI->second;

            // Add call/return edges, not present in intra_edge
            if(auto call = blockCalls.find(from); call != blockCalls.end())
            {
                // Call edge
                cfg[addEdge(from, call->second, cfg)] = true;

                if(auto rets = functionReturns.find(call->second); rets != functionReturns.end())
                {
                    // Return edges
                    for(auto v : rets->second)
                    {
                        addEdge(v, from, cfg);
                    }

                    // Fallthrough to next block after return
                    cfg[addEdge(from, to, cfg)] = false;
                    continue;
                }
            }

            // Add other edges directly from intra_edge
            addEdge(from, to, cfg);
        }
    }

#if 0
    ///////// Print /////////
    for(const auto &b : boost::iterator_range<gtirb::CFG::vertex_iterator>(vertices(cfg)))
    {
        const auto &block = cfg[b];
        std::cout << std::hex << uint64_t(block->getAddress()) << ":\n";
        for(const auto &e : boost::iterator_range<gtirb::CFG::out_edge_iterator>(out_edges(b, cfg)))
        {
            std::cout << "\t" << uint64_t(cfg[target(e, cfg)]->getAddress());
            if(auto *label = std::get_if<bool>(&cfg[e]))
            {
                std::cout << "  " << (*label ? "true" : "false");
            }
            std::cout << "\n";
        }
    }
#endif
}

static void updateComment(std::map<gtirb::Addr, std::string> &comments, gtirb::Addr ea, std::string newComment){
    auto existing=comments.find(ea);
    if(existing != comments.end())
        comments[ea]=existing->second+ newComment;
    else
        comments[ea]=newComment;
}

static void buildComments(gtirb::IR &ir,souffle::SouffleProgram *prog){
    std::map<gtirb::Addr, std::string> comments;
    for(auto &output : *prog->getRelation("data_access_pattern")){
        gtirb::Addr ea;
        uint64_t size, multiplier,from;
        output >> ea >> size >> multiplier >> from;
        std::ostringstream newComment;
        newComment<<"data_access("<<size<<", "<<multiplier<<", "<<std::hex<<from<<std::dec<<") ";
        updateComment(comments, ea, newComment.str());
    }

    for(auto &output : *prog->getRelation("preferred_data_access")){
        gtirb::Addr ea;
        uint64_t data_access;
        output >> ea >> data_access;
        std::ostringstream newComment;
        newComment<<"preferred_data_access("<<std::hex<<data_access<<std::dec<<") ";
        updateComment(comments, ea, newComment.str());
    }

    for(auto &output : *prog->getRelation("best_value_reg")){
        gtirb::Addr ea;
        std::string reg,type;
        int64_t multiplier,offset;
        output >> ea >> reg >> multiplier>> offset >> type;
        std::ostringstream newComment;
        newComment<<reg<<"=X*"<<multiplier<<"+"<<std::hex<<offset<<std::dec<<" type("<<type<<") ";
        updateComment(comments, ea, newComment.str());

    }
    ir.addAuxData("comments", std::move(comments));
}

static void buildIR(gtirb::IR &ir, const std::string &filename, Elf_reader &elf,
                    souffle::SouffleProgram *prog)
{
    auto *M = gtirb::Module::Create(C);
    M->setBinaryPath(filename);
    M->setFileFormat(gtirb::FileFormat::ELF);
    M->setISAID(gtirb::ISAID::X64);
    ir.addModule(M);
    auto symbolSizes = buildSymbols(ir, prog);
    buildSections(ir, elf, prog);
    buildRelocations(ir, prog);
    buildDataGroups(ir, prog, symbolSizes);
    buildCodeBlocks(ir, prog);
    buildFunctions(ir, prog);
    buildCFG(ir, prog);
    buildComments(ir, prog);
}

static void performSanityChecks(souffle::SouffleProgram *prog){
    auto blockOverlap =prog->getRelation("block_still_overlap");
    if(blockOverlap->size()>0){
        std::cerr <<"The conflicts between the following code blocks could not be resolved:"<<std::endl;
        for(auto &output : *blockOverlap){
            uint64_t ea;
            output >> ea;
            std::cerr<< std::hex<<ea<<std::dec<<" ";
        }
        std::cerr <<"Aborting"<<std::endl;
        exit(1);
    }
}

static void decode(Dl_decoder &decoder, Elf_reader &elf, std::vector<std::string> sections,
                   std::vector<std::string> data_sections)
{
    for(const auto &section_name : sections)
    {
        int64_t size;
        uint64_t address;
        char *buff = elf.get_section(section_name, size, address);
        if(buff != nullptr)
        {
            decoder.decode_section(buff, size, address);
            delete[] buff;
        }
        else
        {
            std::cerr << "Section " << section_name << " not found\n";
        }
    }
    uint64_t min_address = elf.get_min_address();
    uint64_t max_address = elf.get_max_address();
    for(const auto &section_name : data_sections)
    {
        int64_t size;
        uint64_t address;
        char *buff = elf.get_section(section_name, size, address);
        if(buff != nullptr)
        {
            decoder.store_data_section(buff, size, address, min_address, max_address);
            delete[] buff;
        }
        else
        {
            std::cerr << "Section " << section_name << " not found\n";
        }
    }
}

static void writeFacts(Dl_decoder &decoder, Elf_reader &elf, const std::string &directory)
{
    std::ios_base::openmode filemask = std::ios::out;

    elf.print_binary_type_to_file(directory + "binary_type.facts");
    elf.print_entry_point_to_file(directory + "entry_point.facts");
    elf.print_sections_to_file(directory + "section.facts");
    elf.print_symbols_to_file(directory + "symbol.facts");
    elf.print_relocations_to_file(directory + "relocation.facts");

    std::ofstream instructions_file(directory + "instruction.facts", filemask);
    decoder.print_instructions(instructions_file);
    instructions_file.close();

    std::ofstream data_file(directory + "address_in_data.facts", filemask);
    decoder.print_data(data_file);
    data_file.close();

    std::ofstream data_bytes_file(directory + "data_byte.facts", filemask);
    decoder.print_data_bytes(data_bytes_file);
    data_bytes_file.close();

    std::ofstream invalids_file(directory + "invalid_op_code.facts", filemask);
    decoder.print_invalids(invalids_file);
    invalids_file.close();

    std::ofstream op_regdirect_file(directory + "op_regdirect.facts", filemask);
    decoder.print_operators_of_type(operator_type::REG, op_regdirect_file);
    op_regdirect_file.close();

    std::ofstream op_immediate_file(directory + "op_immediate.facts", filemask);
    decoder.print_operators_of_type(operator_type::IMMEDIATE, op_immediate_file);
    op_immediate_file.close();

    std::ofstream op_indirect_file(directory + "op_indirect.facts", filemask);
    decoder.print_operators_of_type(operator_type::INDIRECT, op_indirect_file);
    op_indirect_file.close();
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

template <class Func, size_t... Is>
constexpr void static_for(Func &&f, std::integer_sequence<size_t, Is...>)
{
    (f(std::integral_constant<size_t, Is>{}), ...);
}

template <class... T>
souffle::tuple &operator<<(souffle::tuple &t, const std::tuple<T...> &x)
{
    static_for([&t, &x](auto i) { t << get<i>(x); },
               std::make_index_sequence<std::tuple_size<std::tuple<T...>>::value>{});

    return t;
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

static void loadInputs(souffle::SouffleProgram *prog, Elf_reader &elf, const Dl_decoder &decoder)
{
    addRelation<std::string>(prog, "binary_type", {elf.get_binary_type()});
    addRelation<uint64_t>(prog, "entry_point", {elf.get_entry_point()});
    addRelation(prog, "section", elf.get_sections());
    addRelation(prog, "symbol", elf.get_symbols());
    addRelation(prog, "relocation", elf.get_relocations());
    addRelation(prog, "instruction", decoder.instructions);
    addRelation(prog, "address_in_data", decoder.data);
    addRelation(prog, "data_byte", decoder.data_bytes);
    addRelation(prog, "invalid_op_code", decoder.invalids);
    addRelation(prog, "op_regdirect", decoder.op_dict.get_operators_of_type(operator_type::REG));
    addRelation(prog, "op_immediate",
                decoder.op_dict.get_operators_of_type(operator_type::IMMEDIATE));
    addRelation(prog, "op_indirect",
                decoder.op_dict.get_operators_of_type(operator_type::INDIRECT));
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
    std::vector<std::string> sections{".plt.got", ".fini", ".init", ".plt", ".text"};
    std::vector<std::string> dataSections{".data",        ".rodata",  ".fini_array", ".init_array",
                                          ".data.rel.ro", ".got.plt", ".got"};

    po::options_description desc("Allowed options");
    desc.add_options()                                                                    //
        ("help", "produce help message")                                                  //
        ("sect", po::value<std::vector<std::string>>()->default_value(sections),          //
         "sections to decode")                                                            //
        ("data_sect", po::value<std::vector<std::string>>()->default_value(dataSections), //
         "data sections to consider")                                                     //
        ("ir", po::value<std::string>(), "GTIRB output file")                             //
        ("json", po::value<std::string>(), "GTIRB json output file")                             //
        ("asm", po::value<std::string>(), "ASM output file")                              //
        ("debug", "generate assembler file with debugging information")                   //
        ("debug-dir", po::value<std::string>(),                                           //
                 "location to write CSV files for debugging")                             //
        ("input-file", po::value<std::string>(), "file to disasemble")
        ("keep-functions,K", boost::program_options::value<std::vector<std::string>>()->multitoken(),
         "Print the given functions even if they are skipped by default (e.g. _start)");
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

    Elf_reader elf(filename);
    if(!elf.is_valid())
    {
        std::cerr << "There was a problem loading the binary file " << filename << "\n";
        return 1;
    }

    Dl_decoder decoder;
    decode(decoder, elf, vm["sect"].as<std::vector<std::string>>(),
           vm["data_sect"].as<std::vector<std::string>>());
    std::cout<<"Decoding the binary"<<std::endl;
    if(souffle::SouffleProgram *prog = souffle::ProgramFactory::newInstance("souffle_disasm"))
    {
        try
        {
            loadInputs(prog, elf, decoder);
            std::cout<<"Disassembling"<<std::endl;
            prog->run();
            performSanityChecks(prog);

            std::cout<<"Building the gtirb representation"<<std::endl;
            auto &ir = *gtirb::IR::Create(C);
            buildIR(ir, filename, elf, prog);

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
            if(vm.count("keep-functions")!=0){
                for(auto keep: vm["keep-functions"].as<std::vector<std::string>>()){
                    pprinter.keepFunction(keep);
                }
            }
            if(vm.count("asm") != 0)
            {
                std::cout<<"Printing assembler"<<std::endl;
                std::ofstream out(vm["asm"].as<std::string>());
                pprinter.print(out, C, ir);
            }
            else if(vm.count("ir") == 0)
            {
                std::cout<<"Printing assembler"<<std::endl;
                pprinter.print(std::cout, C, ir);
            }

            if(vm.count("debug-dir") != 0)
            {
                std::cout<<"Writing facts to debug dir "<< vm["debug-dir"].as<std::string>()<<std::endl;
                auto dir = vm["debug-dir"].as<std::string>() + "/";
                writeFacts(decoder, elf, dir);
                prog->printAll(dir);
            }

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
