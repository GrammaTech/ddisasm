//===- disasm_main.cpp ------------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2018 GrammaTech, Inc.
//
//  This code is licensed under the GPL V3 license. See the LICENSE file in the
//  project root for license terms.
//
//  This project is sponsored by the Office of Naval Research, One Liberty
//  Center, 875 N. Randolph Street, Arlington, VA 22203 under contract #
//  N68335-17-C-0700.  The content of the information does not necessarily
//  reflect the position or policy of the Government and no official
//  endorsement should be inferred.
//
//===----------------------------------------------------------------------===//
#include <souffle/CompiledSouffle.h>
#include <souffle/SouffleInterface.h>
#include <gtirb/gtirb.hpp>
#include <string>
#include <utility>
#include <vector>
#include "Elf_reader.h"

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

template <>
std::vector<std::string> convertRelation<std::string>(const std::string &relation,
                                                      souffle::SouffleProgram *prog)
{
    std::vector<std::string> result;
    auto *r = prog->getRelation(relation);
    std::transform(r->begin(), r->end(), std::back_inserter(result), [](auto &tuple) {
        std::string str;
        tuple >> str;
        return str;
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
    ir.addTable("functionEAs", std::move(functionEAs));

    return symbolSizes;
}

// Name, Alignment.
const std::array<std::pair<std::string, int>, 7> DataSectionDescriptors{{
    {".got", 8},         //
    {".got.plt", 8},     //
    {".data.rel.ro", 8}, //
    {".init_array", 8},  //
    {".fini_array", 8},  //
    {".rodata", 16},     //
    {".data", 16}        //
}};

static const std::pair<std::string, int> *getDataSectionDescriptor(const std::string &name)
{
    const auto foundDataSection =
        std::find_if(std::begin(DataSectionDescriptors), std::end(DataSectionDescriptors),
                     [name](const auto &dsd) { return dsd.first == name; });
    if(foundDataSection != std::end(DataSectionDescriptors))
        return foundDataSection;
    else
        return nullptr;
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
    ir.addTable("relocations", std::move(relocations));
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
    auto codeInBlock = convertRelation<CodeInBlock>("code_in_block", prog);

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

    for(auto &output : *prog->getRelation("block"))
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
    ir.addTable("blockCalls", std::move(blockCalls));

    std::map<gtirb::Addr, std::string> pltReferences;
    for(const auto &p : symbolicInfo.PLTCodeReferences.contents)
    {
        pltReferences[gtirb::Addr(p.EA)] = p.Name;
    }
    ir.addTable("pltCodeReferences", std::move(pltReferences));
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
    assert(found != sections.end());

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

    ir.addTable("bssData", dataUUIDs);
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

    ir.addTable("dataSections", std::move(dataSections));
    ir.addTable("stringEAs", std::move(stringEAs));

    std::map<gtirb::Addr, std::string> pltReferences;
    for(const auto &p : pltDataReference.contents)
    {
        pltReferences[gtirb::Addr(p.EA)] = p.Name;
    }
    ir.addTable("pltDataReferences", std::move(pltReferences));

    // Set referents of all symbols pointing to data
    std::for_each(module.data_begin(), module.data_end(), [&module](auto &d) {
        auto found = module.findSymbols(d.getAddress());
        std::for_each(found.begin(), found.end(), [&d](auto &sym) { sym.setReferent(&d); });
    });
}

static void buildFunctions(gtirb::IR &ir, souffle::SouffleProgram *prog)
{
    ir.addTable("functionEntry", convertRelation<gtirb::Addr>("function_entry2", prog));
    ir.addTable("mainFunction", convertRelation<gtirb::Addr>("main_function", prog));
    ir.addTable("startFunction", convertRelation<gtirb::Addr>("start_function", prog));
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
    const auto &t2 = *ir.getTable("blockCalls")->get<std::map<gtirb::Addr, gtirb::Addr>>();
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

static void buildIR(gtirb::IR &ir, Elf_reader &elf, souffle::SouffleProgram *prog)
{
    ir.addModule(gtirb::Module::Create(C));
    auto symbolSizes = buildSymbols(ir, prog);
    buildSections(ir, elf, prog);
    buildRelocations(ir, prog);
    buildDataGroups(ir, prog, symbolSizes);
    buildCodeBlocks(ir, prog);
    buildFunctions(ir, prog);
    ir.addTable("ambiguousSymbol", convertRelation<std::string>("ambiguous_symbol", prog));

    buildCFG(ir, prog);
}

int main(int argc, char **argv)
{
    if(argc < 2)
        return 1;

    const char *filename = argv[1];

    souffle::CmdOptions opt(R"(datalog/main.dl)",
                            R"(.)",
                            R"(.)", false,
                            R"()", 1, -1);
    if(!opt.parse(argc - 1, argv + 1))
        return 1;

    Elf_reader elf(filename);
    if(!elf.is_valid())
    {
        std::cerr << "There was a problem loading the binary file " << filename << "\n";
        return 1;
    }

    if(souffle::SouffleProgram *prog = souffle::ProgramFactory::newInstance("souffle_disasm"))
    {
        try
        {
            prog->loadAll(opt.getInputFileDir());
            prog->run();

            // Build and save IR
            auto &ir = *gtirb::IR::Create(C);
            buildIR(ir, elf, prog);

            std::ofstream out(opt.getOutputFileDir() + "/gtirb");
            ir.save(out);

            // Also output CSV files for data not yet stored in gtirb.
            prog->printAll(opt.getOutputFileDir());

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
