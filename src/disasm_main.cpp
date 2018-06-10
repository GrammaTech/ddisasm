#include <souffle/CompiledSouffle.h>
#include <souffle/SouffleInterface.h>
#include <boost/archive/polymorphic_text_oarchive.hpp>
#include <gtirb/Data.hpp>
#include <gtirb/IR.hpp>
#include <gtirb/ImageByteMap.hpp>
#include <gtirb/Module.hpp>
#include <gtirb/Section.hpp>
#include <gtirb/Symbol.hpp>
#include <gtirb/SymbolSet.hpp>
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
    DecodedInstruction(souffle::tuple &tuple)
    {
        assert(tuple.size() == 8);

        tuple >> EA >> Size >> Prefix >> Opcode >> Op1 >> Op2 >> Op3 >> Op4;
    };

    uint64_t getEndAddress() const
    {
        return EA + Size;
    }

    std::string Prefix;
    std::string Opcode;
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
    SymbolicOperand(souffle::tuple &tuple)
    {
        assert(tuple.size() == 2);
        tuple >> EA >> OpNum;
    };

    gtirb::EA EA{0};
    uint64_t OpNum{0};
};

struct SymbolicInfo
{
    std::vector<PLTReference> PLTCodeReferences;
    std::vector<DirectCall> DirectCalls;
    std::vector<MovedLabel> MovedLabels;
    std::vector<SymbolicOperand> SymbolicOperands;
};

struct SymbolicData
{
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

static void buildSymbols(gtirb::IR &ir, souffle::SouffleProgram *prog)
{
    auto syms = ir.getMainModule()->getSymbolSet();

    for(auto &output : *prog->getRelation("symbol"))
    {
        assert(output.size() == 5);

        gtirb::EA base;
        uint64_t size;
        std::string type, scope, name;

        output >> base >> size >> type >> scope >> name;

        auto &new_sym = syms->addSymbol(gtirb::Symbol(base));
        new_sym.setElementSize(size);
        new_sym.setName(name);
        // NOTE: don't seem to care about OBJECT or NOTYPE, and not clear how
        // to represent them in gtirb.
        if(type == "FUNC")
        {
            new_sym.setDeclarationKind(gtirb::Symbol::DeclarationKind::Func);
        }
        // NOTE: don't seem to care about LOCAL or WEAK, and not clear how to
        // represent them in gtirb.
        new_sym.setIsGlobal(scope == "GLOBAL");
    }
}

static void buildSections(gtirb::IR &ir, souffle::SouffleProgram *prog)
{
    auto &sections = ir.getMainModule()->getSections();
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
        return left.startingAddress < right.startingAddress;
    });
}

static void buildRelocations(gtirb::IR &ir, souffle::SouffleProgram *prog)
{
    std::vector<gtirb::Relocation> relocations;
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
    ir.getMainModule()->setRelocations(relocations);
}

void buildDataBytes(gtirb::IR &ir, souffle::SouffleProgram *prog)
{
    auto byteMap = ir.getMainModule()->getImageByteMap();
    for(auto &output : *prog->getRelation("data_byte"))
    {
        gtirb::EA ea;
        uint8_t byte;

        output >> ea >> byte;

        auto minMax = byteMap->getEAMinMax();
        if(minMax.first == gtirb::constants::BadAddress
           && minMax.second == gtirb::constants::BadAddress)
        {
            byteMap->setEAMinMax({ea, ea});
        }
        else
        {
            byteMap->setEAMinMax({std::min(minMax.first, ea), std::max(minMax.second, ea)});
        }

        byteMap->setData(ea, static_cast<uint8_t>(byte));
    }
}

template <typename T>
const T *findByEA(const std::vector<T> &vec, gtirb::EA ea)
{
    const auto found = std::find_if(vec.begin(), vec.end(),
                                    [ea](const auto &element) { return element.EA == ea; });

    if(found != vec.end())
    {
        return &(*found);
    }

    return nullptr;
}

gtirb::Instruction::SymbolicOperand buildSymbolic(gtirb::Instruction &inst, uint64_t operand,
                                                  uint64_t index, const SymbolicInfo &symbolicInfo,
                                                  const std::vector<OpImmediate> &opImmediate,
                                                  const std::vector<OpIndirect> &opIndirect)
{
    if(std::find_if(opImmediate.begin(), opImmediate.end(),
                    [operand](const auto &element) { return element.N == operand; })
       != opImmediate.end())
    {
        auto pltReference = findByEA(symbolicInfo.PLTCodeReferences, inst.getEA());
        if(pltReference != nullptr)
        {
            return {gtirb::Instruction::SymbolicKind::PLTReference, {pltReference->Name}, {}, {}};
        }

        auto directCall = findByEA(symbolicInfo.DirectCalls, inst.getEA());
        if(directCall != nullptr)
        {
            return {gtirb::Instruction::SymbolicKind::DirectCall,
                    {},
                    gtirb::EA(directCall->Destination),
                    {}};
        }

        auto movedLabel = findByEA(symbolicInfo.MovedLabels, inst.getEA());
        if(movedLabel != nullptr)
        {
            return {gtirb::Instruction::SymbolicKind::MovedLabel,
                    {},
                    {},
                    {movedLabel->Offset1, movedLabel->Offset2}};
        }

        if(std::find_if(symbolicInfo.SymbolicOperands.begin(), symbolicInfo.SymbolicOperands.end(),
                        [inst, index](const auto &element) {
                            return (element.EA == inst.getEA()) && (element.OpNum == index);
                        })
           != symbolicInfo.SymbolicOperands.end())
        {
            return {gtirb::Instruction::SymbolicKind::GlobalSymbol};
        }
    }

    if(std::find_if(opIndirect.begin(), opIndirect.end(),
                    [operand](const auto &element) { return element.N == operand; })
       != opIndirect.end())
    {
        auto movedLabel = findByEA(symbolicInfo.MovedLabels, inst.getEA());
        if(movedLabel != nullptr)
        {
            return {gtirb::Instruction::SymbolicKind::MovedLabel,
                    {},
                    {},
                    {movedLabel->Offset1, movedLabel->Offset2}};
        }

        if(std::find_if(symbolicInfo.SymbolicOperands.begin(), symbolicInfo.SymbolicOperands.end(),
                        [inst, index](const auto &element) {
                            return (element.EA == inst.getEA()) && (element.OpNum == index);
                        })
           != symbolicInfo.SymbolicOperands.end())
        {
            return {gtirb::Instruction::SymbolicKind::GlobalSymbol};
        }
    }
    return {gtirb::Instruction::SymbolicKind::None};
}

gtirb::Instruction buildInstruction(gtirb::EA ea, std::vector<DecodedInstruction> instructions,
                                    const SymbolicInfo &symbolicInfo,
                                    const std::vector<OpImmediate> &opImmediate,
                                    const std::vector<OpIndirect> &opIndirect)
{
    const auto inst = std::find_if(instructions.begin(), instructions.end(),
                                   [ea](const auto &x) { return x.EA == ea; });
    assert(inst != instructions.end());

    gtirb::Instruction gtInst(ea);

    auto &symbolic = gtInst.getSymbolicOperands();

    symbolic.push_back(buildSymbolic(gtInst, inst->Op1, 1, symbolicInfo, opImmediate, opIndirect));
    symbolic.push_back(buildSymbolic(gtInst, inst->Op2, 2, symbolicInfo, opImmediate, opIndirect));
    symbolic.push_back(buildSymbolic(gtInst, inst->Op3, 3, symbolicInfo, opImmediate, opIndirect));
    symbolic.push_back(buildSymbolic(gtInst, inst->Op4, 4, symbolicInfo, opImmediate, opIndirect));

    return gtInst;
}

void buildCodeBlocks(gtirb::IR &ir, souffle::SouffleProgram *prog)
{
    auto codeInBlock = convertRelation<CodeInBlock>("code_in_block", prog);

    SymbolicInfo symbolic{convertRelation<PLTReference>("plt_code_reference", prog),
                          convertRelation<DirectCall>("direct_call", prog),
                          convertRelation<MovedLabel>("moved_label", prog),
                          convertRelation<SymbolicOperand>("symbolic_operand", prog)};
    auto decodedInstructions = convertRelation<DecodedInstruction>("instruction", prog);
    auto opImmediate = convertRelation<OpImmediate>("op_immediate", prog);
    auto opIndirect = convertRelation<OpIndirect>("op_indirect", prog);

    std::vector<gtirb::Block> blocks;

    for(auto &output : *prog->getRelation("block"))
    {
        gtirb::EA blockAddress;
        output >> blockAddress;

        std::vector<gtirb::Instruction> instructions;

        for(auto &cib : codeInBlock)
        {
            if(cib.BlockAddress == blockAddress)
            {
                instructions.push_back(buildInstruction(cib.EA, decodedInstructions, symbolic,
                                                        opImmediate, opIndirect));
            }
        }

        std::sort(instructions.begin(), instructions.end(),
                  [](const auto &left, const auto &right) { return left.getEA() < right.getEA(); });

        gtirb::EA end;
        if(!instructions.empty())
        {
            auto address = instructions.back().getEA();
            const auto inst = std::find_if(decodedInstructions.begin(), decodedInstructions.end(),
                                           [address](const auto &x) { return x.EA == address; });
            assert(inst != decodedInstructions.end());

            end = gtirb::EA(address.get() + inst->Size);
        }
        else
        {
            end = gtirb::EA(blockAddress);
        }

        blocks.emplace_back(gtirb::Block(blockAddress, end, instructions));
    }

    std::sort(blocks.begin(), blocks.end(), [](const auto &left, const auto &right) {
        return left.getStartingAddress() < right.getStartingAddress();
    });

    ir.getMainModule()->setBlocks(blocks);
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

void buildDataGroups(gtirb::IR &ir, souffle::SouffleProgram *prog)
{
    std::vector<uint64_t> labeledData;
    for(auto &output : *prog->getRelation("labeled_data"))
    {
        uint64_t x;
        output >> x;
        labeledData.push_back(x);
    }

    auto symbolicData = convertRelation<SymbolicData>("symbolic_data", prog);
    auto pltDataReference = convertRelation<PLTReference>("plt_data_reference", prog);
    auto symbolMinusSymbol = convertRelation<SymbolMinusSymbol>("symbol_minus_symbol", prog);
    auto dataStrings = convertRelation<String>("string", prog);

    std::vector<gtirb::Table::InnerMapType> dataSections;

    for(auto &s : ir.getMainModule()->getSections())
    {
        auto foundDataSection = getDataSectionDescriptor(s.name);

        if(foundDataSection != nullptr)
        {
            gtirb::Table::InnerMapType dataSection;
            dataSection["name"] = s.name;
            dataSection["alignment"] = foundDataSection->second;

            std::vector<uint64_t> dataGroupIndices;

            auto module = ir.getMainModule();
            std::vector<uint8_t> bytes =
                module->getImageByteMap()->getData(s.startingAddress, s.size);

            for(auto currentAddr = s.startingAddress.get(); currentAddr < s.addressLimit();
                currentAddr++)
            {
                gtirb::EA currentEA(currentAddr);

                // Insert a marker for labeled data?
                if(std::find(labeledData.begin(), labeledData.end(), currentAddr)
                   != labeledData.end())
                {
                    dataGroupIndices.push_back(module->getData().size());
                    auto dataGroup = std::make_unique<gtirb::DataLabelMarker>(currentEA);
                    module->addData(std::move(dataGroup));
                }

                // Case 1, 2, 3
                const auto symbolic = findByEA(symbolicData, currentEA);
                if(symbolic != nullptr)
                {
                    // Case 1
                    const auto pltReference = findByEA(pltDataReference, currentEA);
                    if(pltReference != nullptr)
                    {
                        dataGroupIndices.push_back(module->getData().size());
                        auto dataGroup = std::make_unique<gtirb::DataPLTReference>(currentEA);
                        dataGroup->function = pltReference->Name;
                        module->addData(std::move(dataGroup));

                        currentAddr += 7;
                        continue;
                    }

                    // Case 2, 3
                    // There was no PLT Reference and there was no label found.
                    dataGroupIndices.push_back(module->getData().size());
                    auto dataGroup = std::make_unique<gtirb::DataPointer>(currentEA);
                    dataGroup->content = gtirb::EA(symbolic->GroupContent);
                    module->addData(std::move(dataGroup));

                    currentAddr += 7;
                    continue;
                }

                // Case 4, 5
                const auto symMinusSym = findByEA(symbolMinusSymbol, currentEA);
                if(symMinusSym != nullptr)
                {
                    // Case 4, 5
                    dataGroupIndices.push_back(module->getData().size());
                    auto dataGroup = std::make_unique<gtirb::DataPointerDiff>(currentEA);
                    dataGroup->symbol1 = gtirb::EA(symMinusSym->Symbol1);
                    dataGroup->symbol2 = gtirb::EA(symMinusSym->Symbol2);
                    module->addData(std::move(dataGroup));

                    currentAddr += 3;
                    continue;
                }

                // Case 6
                const auto str = findByEA(dataStrings, currentEA);
                if(str != nullptr)
                {
                    dataGroupIndices.push_back(module->getData().size());
                    auto dataGroup = std::make_unique<gtirb::DataString>(currentEA);
                    dataGroup->size = str->End.get() - currentAddr;

                    // Because the loop is going to increment this counter, don't skip a byte.
                    currentAddr = str->End.get() - 1;
                    module->addData(std::move(dataGroup));
                    continue;
                }

                // Store raw data
                dataGroupIndices.push_back(module->getData().size());
                auto dataGroup = std::make_unique<gtirb::DataRawByte>(currentEA);
                module->addData(std::move(dataGroup));
            }

            dataSection["dataGroups"] = dataGroupIndices;
            dataSections.push_back(std::move(dataSection));
        }
    }

    auto table = ir.addTable("DisasmData", std::make_unique<gtirb::Table>());
    table->contents["dataSections"] = dataSections;
}

static void buildIR(gtirb::IR &ir, souffle::SouffleProgram *prog)
{
    buildSymbols(ir, prog);
    buildSections(ir, prog);
    buildRelocations(ir, prog);
    buildDataBytes(ir, prog);
    buildDataGroups(ir, prog);
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
            boost::archive::polymorphic_text_oarchive oa{out};
            oa << ir;
            out.close();

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
