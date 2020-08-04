//===- DatalogLoader.h ------------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2020 GrammaTech, Inc.
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

#include "DatalogLoader.h"
#include "../AuxDataSchema.h"

std::optional<DatalogProgram> DatalogLoader::load(const gtirb::Module& Module)
{
    if(auto SouffleProgram =
           std::shared_ptr<souffle::SouffleProgram>(souffle::ProgramFactory::newInstance(Name)))
    {
        DatalogProgram Program{SouffleProgram};
        for(auto& Loader : Loaders)
        {
            Loader(Module, Program);
        }
        return Program;
    }
    return std::nullopt;
}

void FormatLoader(const gtirb::Module& Module, DatalogProgram& Program)
{
    // Binary architecture.
    std::string BinaryIsa = binaryISA(Module.getISA());

    // Binary file format.
    std::string BinaryFormat = binaryFormat(Module.getFileFormat());

    // Base address.
    gtirb::Addr BaseAddress = Module.getPreferredAddr();

    // Binary entry point.
    gtirb::Addr EntryPoint;
    if(const gtirb::CodeBlock* Block = Module.getEntryPoint())
    {
        if(std::optional<gtirb::Addr> Addr = Block->getAddress())
        {
            EntryPoint = *Addr;
        }
    }

    // Binary object type.
    std::string BinaryType;
    if(auto AuxData = Module.getAuxData<gtirb::schema::BinaryType>())
    {
        for(auto& Type : *AuxData)
        {
            BinaryType = Type;
        }
    }

    Program.insert<std::vector<std::string>>("binary_isa", {BinaryIsa});
    Program.insert<std::vector<std::string>>("binary_type", {BinaryType});
    Program.insert<std::vector<std::string>>("binary_format", {BinaryFormat});
    Program.insert<std::vector<gtirb::Addr>>("base_address", {BaseAddress});
    Program.insert<std::vector<gtirb::Addr>>("entry_point", {EntryPoint});
}

void SymbolLoader(const gtirb::Module& Module, DatalogProgram& Program)
{
    std::vector<relations::Symbol> Symbols;

    for(auto& Symbol : Module.symbols())
    {
        std::string Name = Symbol.getName();
        gtirb::Addr Addr = Symbol.getAddress().value_or(gtirb::Addr(0));
        Symbols.push_back({Addr, 0, "NOTYPE", "GLOBAL", "DEFAULT", 0, Name});
    }

    Program.insert("symbol", std::move(Symbols));
}

void SectionLoader(const gtirb::Module& Module, DatalogProgram& Program)
{
    std::vector<relations::Section> Sections;

    // FIXME: We should either rename this AuxData table or split it.
    auto* SectionProperties = Module.getAuxData<gtirb::schema::ElfSectionProperties>();

    // FIXME: Error handling.
    if(!SectionProperties)
    {
        throw std::logic_error("missing elfSectionProperties AuxData table");
    }

    for(const auto& Section : Module.sections())
    {
        assert(Section.getAddress() && "Section has no address.");
        assert(Section.getSize() && "Section has non-calculable size.");

        auto It = SectionProperties->find(Section.getUUID());

        // FIXME: Error handling.
        if(It == SectionProperties->end())
        {
            throw std::logic_error("Section " + Section.getName()
                                   + " missing from elfSectionProperties AuxData table");
        }

        auto [Type, Flags] = It->second;
        Sections.push_back(
            {Section.getName(), *Section.getSize(), *Section.getAddress(), Type, Flags});
    }

    Program.insert("section_complete", std::move(Sections));
}

void InstructionLoader::operator()(const gtirb::Module& Module, DatalogProgram& Program)
{
    load(Module);

    Program.insert("instruction_complete", Instructions);
    Program.insert("invalid_op_code", InvalidInstructions);
    Program.insert("op_immediate", Operands.ImmTable);
    Program.insert("op_regdirect", Operands.RegTable);
    Program.insert("op_indirect", Operands.IndirectTable);
}

void InstructionLoader::load(const gtirb::Module& Module)
{
    for(const auto& Section : Module.sections())
    {
        bool Executable = Section.isFlagSet(gtirb::SectionFlag::Executable);
        if(Executable)
        {
            for(const auto& ByteInterval : Section.byte_intervals())
            {
                load(ByteInterval);
            }
        }
    }
}

void InstructionLoader::load(const gtirb::ByteInterval& ByteInterval)
{
    assert(ByteInterval.getAddress() && "ByteInterval is non-addressable.");

    uint64_t Addr = static_cast<uint64_t>(*ByteInterval.getAddress());
    uint64_t Size = ByteInterval.getInitializedSize();
    auto Data = ByteInterval.rawBytes<const uint8_t>();

    while(Size > 0)
    {
        if(std::optional<Instruction> Instruction = decode(Data, Size, Addr))
        {
            Instructions.push_back(*Instruction);
        }
        else
        {
            InvalidInstructions.push_back(gtirb::Addr(Addr));
        }
        Addr += InstructionSize;
        Data += InstructionSize;
        Size -= InstructionSize;
    }
}

void DataLoader::operator()(const gtirb::Module& Module, DatalogProgram& Program)
{
    load(Module);

    Program.insert("data_byte", Bytes);
    Program.insert("address_in_data", Addresses);
}

void DataLoader::load(const gtirb::Module& Module)
{
    assert(Module.getSize() && "Module has non-calculable size.");
    Min = *Module.getAddress();

    assert(Module.getAddress() && "Module has non-addressable section data.");
    Max = *Module.getAddress() + *Module.getSize();

    for(const auto& Section : Module.sections())
    {
        bool Executable = Section.isFlagSet(gtirb::SectionFlag::Executable);
        bool Initialized = Section.isFlagSet(gtirb::SectionFlag::Initialized);

        if(Executable || Initialized)
        {
            for(const auto& ByteInterval : Section.byte_intervals())
            {
                assert(ByteInterval.getAddress() && "ByteInterval is non-addressable.");
                load(ByteInterval);
            }
        }
    }
}

void DataLoader::load(const gtirb::ByteInterval& ByteInterval)
{
    gtirb::Addr Addr = *ByteInterval.getAddress();
    uint64_t Size = ByteInterval.getInitializedSize();
    auto Data = ByteInterval.rawBytes<const uint8_t>();

    while(Size > 0)
    {
        // Single byte.
        uint8_t Byte = *Data;
        Bytes.push_back({Addr, Byte});

        // Possible address.
        if(Size >= static_cast<uint64_t>(PointerSize))
        {
            gtirb::Addr Value;

            switch(PointerSize)
            {
                case Pointer::DWORD:
                    Value = gtirb::Addr(*((int32_t*)Data));
                    break;
                case Pointer::QWORD:
                    Value = gtirb::Addr(*((int64_t*)Data));
                    break;
            }

            if(address(Value))
            {
                Addresses.push_back({Addr, Value});
            }
        }

        ++Addr;
        ++Data;
        --Size;
    }
}

const char* binaryFormat(const gtirb::FileFormat Format)
{
    switch(Format)
    {
        case gtirb::FileFormat::COFF:
            return "COFF";
        case gtirb::FileFormat::ELF:
            return "ELF";
        case gtirb::FileFormat::PE:
            return "PE";
        case gtirb::FileFormat::IdaProDb32:
            return "IdaProDb32";
        case gtirb::FileFormat::IdaProDb64:
            return "IdaProDb64";
        case gtirb::FileFormat::XCOFF:
            return "XCOFF";
        case gtirb::FileFormat::MACHO:
            return "MACHO";
        case gtirb::FileFormat::RAW:
            return "RAW";
        case gtirb::FileFormat::Undefined:
        default:
            return "Undefined";
    }
}

const char* binaryISA(gtirb::ISA Arch)
{
    switch(Arch)
    {
        case gtirb::ISA::X64:
            return "X64";
        case gtirb::ISA::ARM64:
            return "ARM";
        default:
            return "Undefined";
    }
}

std::string uppercase(std::string S)
{
    std::transform(S.begin(), S.end(), S.begin(),
                   [](unsigned char C) { return static_cast<unsigned char>(std::toupper(C)); });
    return S;
};
