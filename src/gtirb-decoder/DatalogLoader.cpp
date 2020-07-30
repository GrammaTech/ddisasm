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

std::optional<DatalogProgram> DatalogLoader::program()
{
    // Build the Souffle context.
    if(auto SouffleProgram =
           std::shared_ptr<souffle::SouffleProgram>(souffle::ProgramFactory::newInstance(Name)))
    {
        DatalogProgram Program{SouffleProgram};
        for(auto& Decoder : Decoders)
        {
            Decoder->populate(Program);
        }
        return Program;
    }
    return std::nullopt;
}

void DatalogLoader::decode(const gtirb::Module& Module)
{
    for(auto& Decoder : Decoders)
    {
        if(Decoder)
        {
            Decoder->load(Module);
        }
    }
}

void FormatDecoder::load(const gtirb::Module& Module)
{
    // Binary architecture.
    BinaryIsa = binaryISA(Module.getISA());

    // Binary file format.
    BinaryFormat = binaryFormat(Module.getFileFormat());

    // Base address.
    BaseAddress = Module.getPreferredAddr();

    // Binary entry point.
    if(const gtirb::CodeBlock* Block = Module.getEntryPoint())
    {
        if(std::optional<gtirb::Addr> Addr = Block->getAddress())
        {
            EntryPoint = *Addr;
        }
    }

    // Binary object type.
    if(auto AuxData = Module.getAuxData<gtirb::schema::BinaryType>())
    {
        // FIXME: Change AuxData type to a plain string.
        for(auto& Type : *AuxData)
        {
            BinaryType = Type;
        }
    }
}

void FormatDecoder::populate(DatalogProgram& Program)
{
    Program.insert<std::vector<std::string>>("binary_type", {BinaryIsa});
    Program.insert<std::vector<std::string>>("binary_format", {BinaryFormat});
    Program.insert<std::vector<gtirb::Addr>>("base_address", {BaseAddress});
    Program.insert<std::vector<gtirb::Addr>>("entry_point", {EntryPoint});
}

void SymbolDecoder::load(const gtirb::Module& Module)
{
    for(auto& Symbol : Module.symbols())
    {
        std::string Name = Symbol.getName();
        gtirb::Addr Addr = Symbol.getAddress().value_or(gtirb::Addr(0));
        Symbols.push_back({Addr, 0, "NOTYPE", "GLOBAL", "DEFAULT", 0, Name});
    }
}

void SymbolDecoder::populate(DatalogProgram& Program)
{
    Program.insert("symbol", Symbols);
}

void SectionDecoder::load(const gtirb::Module& Module)
{
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
}

void SectionDecoder::populate(DatalogProgram& Program)
{
    Program.insert("section_complete", Sections);
}

void InstructionDecoder::load(const gtirb::Module& Module)
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

void InstructionDecoder::load(const gtirb::ByteInterval& ByteInterval)
{
    assert(ByteInterval.getAddress() && "ByteInterval is non-addressable.");

    uint64_t Addr = static_cast<uint64_t>(*ByteInterval.getAddress());
    uint64_t Size = ByteInterval.getInitializedSize();
    auto Data = ByteInterval.rawBytes<const uint8_t>();

    while(Size > 0)
    {
        if(std::optional<Instruction> Instruction = disasm(Data, Size, Addr))
        {
            Instructions.push_back(*Instruction);
        }
        else
        {
            InvalidInstructions.push_back(gtirb::Addr(Addr));
        }
        ++Addr;
        ++Data;
        --Size;
    }
}

void InstructionDecoder::populate(DatalogProgram& Program)
{
    Program.insert("instruction_complete", Instructions);
    Program.insert("invalid_op_code", InvalidInstructions);
    Program.insert("op_immediate", Operands.ImmTable);
    Program.insert("op_regdirect", Operands.RegTable);
    Program.insert("op_indirect", Operands.IndirectTable);
}

void DataDecoder::load(const gtirb::Module& Module)
{
    for(const auto& Section : Module.sections())
    {
        bool Initialized = Section.isFlagSet(gtirb::SectionFlag::Initialized);
        bool Executable = Section.isFlagSet(gtirb::SectionFlag::Executable);

        if(Executable || Initialized)
        {
            for(const auto& ByteInterval : Section.byte_intervals())
            {
                load(ByteInterval);
            }
        }
    }
}

void DataDecoder::load(const gtirb::ByteInterval& ByteInterval)
{
    assert(ByteInterval.getAddress() && "ByteInterval is non-addressable.");

    const gtirb::Section* Section = ByteInterval.getSection();
    assert(Section && "ByteInterval does not belong to a Section.");

    const gtirb::Module* Module = Section->getModule();
    assert(Module && "Section does not belong to a Module.");

    assert(Module->getSize() && "Module has non-calculable size.");
    gtirb::Addr Start = *Module->getAddress();

    assert(Module->getAddress() && "Module has non-addressable section data.");
    gtirb::Addr End = *Module->getAddress() + *Module->getSize();

    auto PossibleAddress = [Start, End](gtirb::Addr Value) {
        return ((Value >= Start) && (Value <= Value));
    };

    gtirb::Addr Addr = *ByteInterval.getAddress();
    uint64_t Size = ByteInterval.getInitializedSize();
    auto Data = ByteInterval.rawBytes<const uint8_t>();

    // FIXME: Window size should be respective the architecture.
    while(Size >= 8)
    {
        // Store single byte.
        uint8_t Byte = *Data;
        Bytes.push_back({Addr, Byte});

        // Store address.
        if(Size >= 8)
        {
            gtirb::Addr Value(*((int64_t*)Data));
            if(PossibleAddress(Value))
            {
                Addresses.push_back({Addr, Value});
            }
        }

        ++Addr;
        ++Data;
        --Size;
    }
}

void DataDecoder::populate(DatalogProgram& Program)
{
    Program.insert("data_byte", Bytes);
    Program.insert("address_in_data", Addresses);
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

namespace souffle
{
    souffle::tuple& operator<<(souffle::tuple& T, const gtirb::Addr& A)
    {
        T << static_cast<uint64_t>(A);
        return T;
    }

    souffle::tuple& operator<<(souffle::tuple& T, const SymbolDecoder::Symbol& Symbol)
    {
        T << Symbol.Addr << Symbol.Size << Symbol.Type << Symbol.Binding << Symbol.SectionIndex
          << Symbol.Name;
        return T;
    }

    souffle::tuple& operator<<(souffle::tuple& T, const SectionDecoder::Section& Section)
    {
        T << Section.Name << Section.Size << Section.Address << Section.Type << Section.Flags;
        return T;
    }

    template <typename Item>
    souffle::tuple& operator<<(souffle::tuple& T, const DataDecoder::Data<Item>& Data)
    {
        T << Data.Addr << Data.Item;
        return T;
    }

    souffle::tuple& operator<<(souffle::tuple& T,
                               const InstructionDecoder::Instruction& Instruction)
    {
        T << Instruction.Address << Instruction.Size << Instruction.Prefix << Instruction.Name;
        for(size_t i = 0; i < 4; ++i)
        {
            if(i < Instruction.OpCodes.size())
            {
                T << Instruction.OpCodes[i];
            }
            else
            {
                T << 0;
            }
        }
        T << Instruction.ImmediateOffset << Instruction.DisplacementOffset;
        return T;
    }

    souffle::tuple& operator<<(souffle::tuple& T, const InstructionDecoder::IndirectOp& Op)
    {
        T << Op.Reg1 << Op.Reg2 << Op.Reg3 << Op.Mult << Op.Disp << Op.Size;
        return T;
    }

    template <class U>
    souffle::tuple& operator<<(souffle::tuple& T, const std::pair<U, uint64_t>& Pair)
    {
        auto& [Element, Id] = Pair;
        T << Id << Element;
        return T;
    }
} // namespace souffle
