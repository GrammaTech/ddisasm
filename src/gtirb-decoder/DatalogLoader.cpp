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

const char* format(const gtirb::FileFormat Format)
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

const char* isa(gtirb::ISA Arch)
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

void DatalogLoader::load(const gtirb::Module& Module)
{
    for(std::shared_ptr<GtirbDecoder> Decoder : Decoders)
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
    BinaryIsa = isa(Module.getISA());

    // Binary file format.
    BinaryFormat = format(Module.getFileFormat());

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
        // FIXME: Change toe AuxData type to a plain string.
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
    Program.insert<std::vector<gtirb::Addr>>("entry_point", {EntryPoint});
}

void SectionDecoder::load(const gtirb::Module& Module)
{
    for(const auto& Section : Module.sections())
    {
        bool Executable = Section.isFlagSet(gtirb::SectionFlag::Executable);
        bool Initialized = Section.isFlagSet(gtirb::SectionFlag::Initialized);

        if(Executable)
        {
            for(const auto& ByteInterval : Section.byte_intervals())
            {
                Code.load(ByteInterval);
                Data.load(ByteInterval);
            }
        }
        else if(Initialized)
        {
            for(const auto& ByteInterval : Section.byte_intervals())
            {
                Data.load(ByteInterval);
            }
        }
    }
}

void SectionDecoder::populate(DatalogProgram& Program)
{
    Code.populate(Program);
    Data.populate(Program);
}

void InstructionDecoder::load(const gtirb::ByteInterval& ByteInterval)
{
    assert(ByteInterval.getAddress() && "ByteInterval is non-addressable.");

    gtirb::Addr Addr = *ByteInterval.getAddress();
    uint64_t Size = ByteInterval.getInitializedSize();
    auto Data = ByteInterval.rawBytes<const uint8_t>();

    while(Size > 0)
    {
        if(std::optional<Instruction> Instruction = decode(Data, Size))
        {
            Instructions.push_back(*Instruction);
        }
        else
        {
            InvalidInstructions.push_back(Addr);
        }
        ++Addr;
        ++Data;
        --Size;
    }
}

void InstructionDecoder::populate(DatalogProgram& Program)
{
    // Program.insert("instruction_complete", Instructions);
    // Program.insert("invalid_op_code", InvalidInstructions);
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
