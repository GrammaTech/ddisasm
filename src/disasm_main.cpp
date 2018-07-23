#include <souffle/CompiledSouffle.h>
#include <souffle/SouffleInterface.h>
#include <gtirb/Block.hpp>
#include <gtirb/Data.hpp>
#include <gtirb/IR.hpp>
#include <gtirb/ImageByteMap.hpp>
#include <gtirb/Module.hpp>
#include <gtirb/Relocation.hpp>
#include <gtirb/Section.hpp>
#include <gtirb/Symbol.hpp>
#include <gtirb/SymbolicOperand.hpp>
#include <gtirb/Table.hpp>
#include <string>
#include <vector>

// souffle uses a signed integer for all numbers (either 32 or 64 bits
// dependin on compilation flags). Allow conversion to other types.
souffle::tuple &operator>>(souffle::tuple &t, uint64_t &number)
{
    int64_t x;
    t >> x;
    number = x;
    return t;
}

souffle::tuple &operator>>(souffle::tuple &t, gtirb::EA &ea)
{
    uint64_t x;
    t >> x;
    ea = gtirb::EA(x);
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
    DecodedInstruction(uint64_t ea) : EA(ea)
    {
    }

    DecodedInstruction(souffle::tuple &tuple)
    {
        assert(tuple.size() == 8);

        tuple >> EA >> Size;
        // Skip prefix and opcode. Not used.
        this->Op1 = tuple[4];
        this->Op2 = tuple[5];
        this->Op3 = tuple[6];
        this->Op4 = tuple[7];
    };

    uint64_t getEndAddress() const
    {
        return EA + Size;
    }

    uint64_t EA{0};
    uint64_t Size{0};
    uint64_t Op1{0};
    uint64_t Op2{0};
    uint64_t Op3{0};
    uint64_t Op4{0};
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

    gtirb::EA EA{0};
    gtirb::EA BlockAddress{0};
};

struct PLTReference
{
    PLTReference(uint64_t ea) : EA(ea)
    {
    }

    PLTReference(souffle::tuple &tuple)
    {
        assert(tuple.size() == 2);
        tuple >> EA >> Name;
    };

    std::string Name;
    gtirb::EA EA{0};
};

struct DirectCall
{
    DirectCall(uint64_t ea) : EA(ea)
    {
    }

    DirectCall(souffle::tuple &tuple)
    {
        assert(tuple.size() == 2);

        tuple >> EA >> Destination;
    };

    gtirb::EA EA{0};
    gtirb::EA Destination{0};
};

struct MovedLabel
{
    MovedLabel(uint64_t ea) : EA(ea)
    {
    }

    MovedLabel(souffle::tuple &tuple)
    {
        assert(tuple.size() == 4);
        tuple >> EA >> N >> Offset1 >> Offset2;
    };

    gtirb::EA EA{0};
    uint64_t N{0};
    int64_t Offset1{0};
    int64_t Offset2{0};
};

struct SymbolicOperand
{
    SymbolicOperand(uint64_t ea) : EA(ea)
    {
    }
    SymbolicOperand(souffle::tuple &tuple)
    {
        assert(tuple.size() == 2);
        tuple >> EA >> OpNum;
    };

    gtirb::EA EA{0};
    uint64_t OpNum{0};
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

    std::pair<const_iterator, const_iterator> equal_range(gtirb::EA ea) const
    {
        T key(ea);
        return std::equal_range(
            this->contents.begin(), this->contents.end(), key,
            [](const auto &left, const auto &right) { return left.EA < right.EA; });
    }

    const T *find(gtirb::EA ea) const
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
    VectorByEA<SymbolicOperand> SymbolicOperands;
};

struct SymbolicData
{
    SymbolicData(uint64_t ea) : EA(ea)
    {
    }

    SymbolicData(souffle::tuple &tuple)
    {
        assert(tuple.size() == 2);
        tuple >> EA >> GroupContent;
    };

    gtirb::EA EA{0};
    uint64_t GroupContent{0};
};

struct SymbolMinusSymbol
{
    SymbolMinusSymbol(uint64_t ea) : EA(ea)
    {
    }

    SymbolMinusSymbol(souffle::tuple &tuple)
    {
        assert(tuple.size() == 3);

        tuple >> EA >> Symbol1 >> Symbol2;
    };

    gtirb::EA EA{0};
    gtirb::EA Symbol1{0};
    gtirb::EA Symbol2{0};
};

// "String" is a bad name for this data type.
struct String
{
    String(uint64_t ea) : EA(ea)
    {
    }

    String(souffle::tuple &tuple)
    {
        assert(tuple.size() == 2);

        tuple >> EA >> End;
    };

    gtirb::EA EA{0};
    gtirb::EA End{0};
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

static std::map<uint64_t, uint64_t> buildSymbols(gtirb::IR &ir, souffle::SouffleProgram *prog)
{
    std::map<uint64_t, uint64_t> symbolSizes;
    auto &syms = ir.getMainModule().getSymbolSet();
    std::vector<gtirb::EA> functionEAs;

    for(auto &output : *prog->getRelation("symbol"))
    {
        assert(output.size() == 5);

        gtirb::EA base;
        uint64_t size;
        std::string type, scope, name;

        output >> base >> size >> type >> scope >> name;

        gtirb::Symbol new_sym(base, name);
        symbolSizes[base] = size;
        new_sym.setName(name);
        // NOTE: don't seem to care about OBJECT or NOTYPE, and not clear how
        // to represent them in gtirb.
        if(type == "FUNC")
        {
            functionEAs.push_back(base);
        }

        new_sym.setStorageKind(scope == "GLOBAL" ? gtirb::Symbol::StorageKind::Extern
                                                 : gtirb::Symbol::StorageKind::Local);

        addSymbol(syms, std::move(new_sym));
    }

    std::sort(functionEAs.begin(), functionEAs.end());
    ir.addTable("functionEAs", std::make_unique<gtirb::Table>(std::move(functionEAs)));

    return symbolSizes;
}

static void buildSections(gtirb::IR &ir, souffle::SouffleProgram *prog)
{
    auto &sections = ir.getMainModule().getSections();
    for(auto &output : *prog->getRelation("section"))
    {
        assert(output.size() == 3);

        gtirb::EA address;
        uint64_t size;
        std::string name;
        output >> name >> size >> address;
        sections.emplace_back(name, size, address);
    }
    std::sort(sections.begin(), sections.end(), [](const auto &left, const auto &right) {
        return left.getStartingAddress() < right.getStartingAddress();
    });
}

static void buildRelocations(gtirb::IR &ir, souffle::SouffleProgram *prog)
{
    auto &relocations = ir.getMainModule().getRelocations();
    for(auto &output : *prog->getRelation("relocation"))
    {
        gtirb::EA ea;
        uint64_t offset;
        std::string type, name;
        output >> ea >> type >> name >> offset;
        // Datalog code turns empty string in "n/a" somewhere. Put it back.
        if(name == "n/a")
            name.clear();
        relocations.push_back({ea, type, name, static_cast<uint64_t>(offset)});
    }
}

void buildDataBytes(gtirb::IR &ir, souffle::SouffleProgram *prog)
{
    auto &byteMap = ir.getMainModule().getImageByteMap();
    for(auto &output : *prog->getRelation("data_byte"))
    {
        gtirb::EA ea;
        uint8_t byte;

        output >> ea >> byte;

        auto minMax = byteMap.getEAMinMax();
        if(minMax.first == gtirb::constants::BadAddress
           && minMax.second == gtirb::constants::BadAddress)
        {
            byteMap.setEAMinMax({ea, ea});
        }
        else
        {
            byteMap.setEAMinMax({std::min(minMax.first, ea), std::max(minMax.second, ea)});
        }

        byteMap.setData(ea, static_cast<uint8_t>(byte));
    }
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

static const gtirb::NodeReference<gtirb::Symbol> getSymbol(gtirb::SymbolSet &symbols, gtirb::EA ea)
{
    const auto found = gtirb::findSymbols(symbols, ea);
    if(!found.empty())
    {
        return gtirb::NodeReference<gtirb::Symbol>(*found[0]);
    }

    gtirb::Symbol sym(ea, getLabel(ea));
    sym.setStorageKind(gtirb::Symbol::StorageKind::Local);
    gtirb::NodeReference<gtirb::Symbol> result(sym);
    gtirb::addSymbol(symbols, std::move(sym));

    return result;
}

void buildSymbolic(gtirb::SymbolSet &symbols, gtirb::SymbolicOperandSet &symbolic,
                   DecodedInstruction instruction, gtirb::EA &ea, uint64_t operand, uint64_t index,
                   const SymbolicInfo &symbolicInfo, const VectorByN<OpImmediate> &opImmediate,
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
            auto sym = getSymbol(symbols, gtirb::EA(immediate));
            symbolic.insert({gtirb::EA(ea.get() + index), gtirb::SymAddrConst{0, sym}});
        }

        auto directCall = symbolicInfo.DirectCalls.find(ea);
        if(directCall != nullptr)
        {
            auto sym = getSymbol(symbols, directCall->Destination);
            symbolic.insert({gtirb::EA(ea.get() + index), gtirb::SymAddrConst{0, sym}});
        }

        auto movedLabel = symbolicInfo.MovedLabels.find(ea);
        if(movedLabel != nullptr)
        {
            assert(movedLabel->Offset1 == immediate);
            auto diff = movedLabel->Offset1 - movedLabel->Offset2;
            auto sym = getSymbol(symbols, gtirb::EA(movedLabel->Offset2));
            symbolic.insert({gtirb::EA(ea.get() + index), gtirb::SymAddrConst{diff, sym}});
        }

        auto range = symbolicInfo.SymbolicOperands.equal_range(ea);
        if(std::find_if(range.first, range.second,
                        [ea, index](const auto &element) {
                            return (element.EA == ea) && (element.OpNum == index);
                        })
           != range.second)
        {
            auto sym = getSymbol(symbols, gtirb::EA(immediate));
            symbolic.insert({gtirb::EA(ea.get() + index), gtirb::SymAddrConst{0, sym}});
        }
    }

    const auto foundInd = opIndirect.find(operand);

    if(foundInd != nullptr)
    {
        auto op = *foundInd;
        auto movedLabel = symbolicInfo.MovedLabels.find(ea);
        if(movedLabel != nullptr)
        {
            auto diff = movedLabel->Offset1 - movedLabel->Offset2;
            auto sym = getSymbol(symbols, gtirb::EA(movedLabel->Offset2));
            symbolic.insert({gtirb::EA(ea.get() + index), gtirb::SymAddrConst{diff, sym}});
        }

        auto range = symbolicInfo.SymbolicOperands.equal_range(ea);
        if(std::find_if(range.first, range.second,
                        [ea, index](const auto &element) {
                            return (element.EA == ea) && (element.OpNum == index);
                        })
           != range.second)
        {
            if(op.Reg1 == std::string{"RIP"} && op.Multiplier == 1 && isNullReg(op.SReg)
               && isNullReg(op.Reg2))
            {
                auto address = gtirb::EA(ea.get() + foundInd->Offset + instruction.Size);
                auto sym = getSymbol(symbols, address);
                symbolic.insert({gtirb::EA(ea.get() + index), gtirb::SymAddrConst{0, sym}});
            }
            else
            {
                auto sym = getSymbol(symbols, gtirb::EA(op.Offset));
                symbolic.insert({gtirb::EA(ea.get() + index), gtirb::SymAddrConst{0, sym}});
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
        convertSortedRelation<VectorByEA<SymbolicOperand>>("symbolic_operand", prog)};
    auto decodedInstructions =
        convertSortedRelation<VectorByEA<DecodedInstruction>>("instruction", prog);
    auto opImmediate = convertSortedRelation<VectorByN<OpImmediate>>("op_immediate", prog);
    auto opIndirect = convertSortedRelation<VectorByN<OpIndirect>>("op_indirect", prog);

    auto &module = ir.getMainModule();
    std::vector<gtirb::Block> blocks;
    auto &cfg = module.getCFG();
    auto &symbolic = module.getSymbolicOperands();
    auto &symbols = module.getSymbolSet();

    for(auto &output : *prog->getRelation("block"))
    {
        gtirb::EA blockAddress;
        output >> blockAddress;

        std::vector<gtirb::Instruction> instructions;

        for(auto &cib : codeInBlock)
        {
            if(cib.BlockAddress == blockAddress)
            {
                const auto inst = decodedInstructions.find(cib.EA);
                assert(inst != nullptr);

                instructions.emplace_back(gtirb::EA(cib.EA));
                buildSymbolic(symbols, symbolic, *inst, cib.EA, inst->Op1, 1, symbolicInfo,
                              opImmediate, opIndirect);
                buildSymbolic(symbols, symbolic, *inst, cib.EA, inst->Op2, 2, symbolicInfo,
                              opImmediate, opIndirect);
                buildSymbolic(symbols, symbolic, *inst, cib.EA, inst->Op3, 3, symbolicInfo,
                              opImmediate, opIndirect);
                buildSymbolic(symbols, symbolic, *inst, cib.EA, inst->Op4, 4, symbolicInfo,
                              opImmediate, opIndirect);
            }
        }

        std::sort(instructions.begin(), instructions.end(),
                  [](const auto &left, const auto &right) { return left.getEA() < right.getEA(); });

        gtirb::EA end;
        if(!instructions.empty())
        {
            auto address = instructions.back().getEA();
            const auto inst = decodedInstructions.find(address);
            assert(inst != nullptr);

            end = gtirb::EA(address.get() + inst->Size);
        }
        else
        {
            end = gtirb::EA(blockAddress);
        }

        blocks.emplace_back(blockAddress, end, std::move(instructions));
    }

    std::sort(blocks.begin(), blocks.end(), [](const auto &left, const auto &right) {
        return left.getStartingAddress() < right.getStartingAddress();
    });
    std::for_each(blocks.begin(), blocks.end(),
                  [&cfg](auto &&b) { gtirb::addBlock(cfg, std::move(b)); });

    std::map<gtirb::EA, gtirb::table::ValueType> pltReferences;
    for(const auto &p : symbolicInfo.PLTCodeReferences.contents)
    {
        pltReferences[gtirb::EA(p.EA)] = p.Name;
    }
    ir.addTable("pltCodeReferences", std::make_unique<gtirb::Table>(std::move(pltReferences)));
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

const std::pair<std::string, int> *getDataSectionDescriptor(const std::string &name)
{
    const auto foundDataSection =
        std::find_if(std::begin(DataSectionDescriptors), std::end(DataSectionDescriptors),
                     [name](const auto &dsd) { return dsd.first == name; });
    if(foundDataSection != std::end(DataSectionDescriptors))
        return foundDataSection;
    else
        return nullptr;
}

// Create Data objects for labeled objects in the BSS section, without adding
// data to the ImageByteMap.
void buildBSS(const gtirb::IR &ir, gtirb::DataSet &data, souffle::SouffleProgram *prog,
              const std::map<uint64_t, uint64_t> &symbolSizes)
{
    std::vector<uint64_t> bssData;
    auto relation = prog->getRelation("bss_data");
    std::transform(relation->begin(), relation->end(), std::back_inserter(bssData),
                   [](auto &tuple) {
                       uint64_t result;
                       tuple >> result;
                       return result;
                   });

    if(bssData.empty())
    {
        return;
    }

    const auto &sections = ir.getMainModule().getSections();
    const auto found = std::find_if(sections.begin(), sections.end(), [](const auto &element) {
        return element.getName() == ".bss";
    });
    assert(found != sections.end());

    for(size_t i = 0; i < bssData.size(); ++i)
    {
        const uint64_t current = bssData[i];

        if(i != bssData.size() - 1)
        {
            uint64_t next = bssData[i + 1];

            // If there's a symbol at this location, adjust Data object to
            // match symbol size.
            auto symbol = symbolSizes.find(current);
            if(symbol != symbolSizes.end())
            {
                uint64_t size = symbol->second;
                uint64_t end = current + size;
                data.emplace_back(gtirb::EA(current), size);
                // If symbol size was smaller than BSS object, fill in the
                // difference
                if(end < next)
                {
                    data.emplace_back(gtirb::EA(end), next - end);
                }
                // Otherwise, skip BSS objects contained within the symbol.
                else
                {
                    while(bssData[i] < end)
                    {
                        i++;
                    }
                }
            }
            else
            {
                data.emplace_back(gtirb::EA(current), next - current);
            }
        }
        else
        {
            // Print to the end of the section.
            uint64_t next = found->addressLimit().get();
            data.emplace_back(gtirb::EA(current), next - current);
        }
    }
}

void buildDataGroups(gtirb::IR &ir, souffle::SouffleProgram *prog,
                     const std::map<uint64_t, uint64_t> &symbolSizes)
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
    auto symbolMinusSymbol =
        convertSortedRelation<VectorByEA<SymbolMinusSymbol>>("symbol_minus_symbol", prog);
    auto dataStrings = convertSortedRelation<VectorByEA<String>>("string", prog);
    auto &module = ir.getMainModule();
    auto &symbols = module.getSymbolSet();
    auto &symbolicOps = module.getSymbolicOperands();
    auto &data = module.getData();

    std::vector<gtirb::table::InnerMapType> dataSections;
    std::vector<gtirb::EA> stringEAs;

    for(auto &s : module.getSections())
    {
        auto foundDataSection = getDataSectionDescriptor(s.getName());

        if(foundDataSection != nullptr)
        {
            gtirb::table::InnerMapType dataSection;
            dataSection["name"] = s.getName();
            dataSection["alignment"] = foundDataSection->second;

            std::vector<int64_t> dataGroupIndices;

            std::vector<uint8_t> bytes =
                module.getImageByteMap().getData(s.getStartingAddress(), s.getSize());

            for(auto currentAddr = s.getStartingAddress().get(); currentAddr < s.addressLimit();
                currentAddr++)
            {
                gtirb::EA currentEA(currentAddr);

                // Case 1, 2, 3
                const auto symbolic = symbolicData.find(currentEA);
                if(symbolic != nullptr)
                {
                    // Case 1
                    const auto pltReference = pltDataReference.find(currentEA);
                    if(pltReference != nullptr)
                    {
                        dataGroupIndices.push_back(data.size());
                        data.emplace_back(currentEA, 8);

                        currentAddr += 7;
                        continue;
                    }

                    // Case 2, 3
                    // There was no PLT Reference and there was no label found.
                    dataGroupIndices.push_back(data.size());
                    data.emplace_back(currentEA, 8);

                    symbolicOps.insert(
                        {gtirb::EA(currentEA),
                         gtirb::SymAddrConst{
                             0, getSymbol(symbols, gtirb::EA(symbolic->GroupContent))}});

                    currentAddr += 7;
                    continue;
                }

                // Case 4, 5
                const auto symMinusSym = symbolMinusSymbol.find(currentEA);
                if(symMinusSym != nullptr)
                {
                    // Case 4, 5
                    dataGroupIndices.push_back(data.size());
                    data.emplace_back(currentEA, 4);

                    symbolicOps.insert(
                        {gtirb::EA(currentEA),
                         gtirb::SymAddrAddr{1, 0, getSymbol(symbols, symMinusSym->Symbol2),
                                            getSymbol(symbols, symMinusSym->Symbol1)}});

                    currentAddr += 3;
                    continue;
                }

                // Case 6
                const auto str = dataStrings.find(currentEA);
                if(str != nullptr)
                {
                    dataGroupIndices.push_back(data.size());
                    stringEAs.push_back(currentEA);
                    data.emplace_back(currentEA, str->End.get() - currentAddr);

                    // Because the loop is going to increment this counter, don't skip a byte.
                    currentAddr = str->End.get() - 1;

                    continue;
                }

                // Store raw data
                dataGroupIndices.push_back(data.size());
                data.emplace_back(currentEA, 1);
            }

            dataSection["dataGroups"] = dataGroupIndices;
            dataSections.push_back(std::move(dataSection));
        }
    }

    buildBSS(ir, data, prog, symbolSizes);

    ir.addTable("dataSections", std::make_unique<gtirb::Table>(std::move(dataSections)));
    ir.addTable("stringEAs", std::make_unique<gtirb::Table>(std::move(stringEAs)));

    std::map<gtirb::EA, gtirb::table::ValueType> pltReferences;
    for(const auto &p : pltDataReference.contents)
    {
        pltReferences[gtirb::EA(p.EA)] = p.Name;
    }
    ir.addTable("pltDataReferences", std::make_unique<gtirb::Table>(std::move(pltReferences)));

    // Set referents of all symbols pointing to data
    std::for_each(data.begin(), data.end(), [&symbols](const auto &d) {
        auto found = gtirb::findSymbols(symbols, d.getEA());
        std::for_each(found.begin(), found.end(), [&d](auto &sym) { sym->setReferent(d); });
    });
}

static void buildIR(gtirb::IR &ir, souffle::SouffleProgram *prog)
{
    auto symbolSizes = buildSymbols(ir, prog);
    buildSections(ir, prog);
    buildRelocations(ir, prog);
    buildDataBytes(ir, prog);
    buildDataGroups(ir, prog, symbolSizes);
    buildCodeBlocks(ir, prog);
}

int main(int argc, char **argv)
{
    souffle::CmdOptions opt(R"(datalog/main.dl)",
                            R"(.)",
                            R"(.)", false,
                            R"()", 1, -1);
    if(!opt.parse(argc, argv))
        return 1;

    if(souffle::SouffleProgram *prog =
           souffle::ProgramFactory::newInstance("___bin_souffle_disasm"))
    {
        try
        {
            prog->loadAll(opt.getInputFileDir());
            prog->run();

            // Build and save IR
            gtirb::IR ir;
            buildIR(ir, prog);

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
