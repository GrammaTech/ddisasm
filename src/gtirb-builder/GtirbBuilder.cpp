//===- GtirbBuilder.cpp  ----------------------------------------*- C++ -*-===//
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
#include "./GtirbBuilder.h"

#include "./ArchiveReader.h"
#include "./ElfReader.h"
#include "./PeReader.h"

using GTIRB = GtirbBuilder::GTIRB;

gtirb::ErrorOr<GTIRB> GtirbBuilder::read(std::string Path)
{
    // Check that the file exists.
    if(!fs::exists(Path))
    {
        return GtirbBuilder::build_error::FileNotFound;
    }

    auto Context = std::make_shared<gtirb::Context>();

    // Parse an input binary with LIEF.
    if(LIEF::ELF::is_elf(Path) || LIEF::PE::is_pe(Path))
    {
        gtirb::IR* IR = gtirb::IR::Create(*Context);

        std::shared_ptr<LIEF::Binary> Binary{
            LIEF::ELF::is_elf(Path) ? LIEF::ELF::Parser::parse(Path) : LIEF::Parser::parse(Path)};

        // If the binary had no sections, parse again with AUTO count method.
        if(LIEF::ELF::is_elf(Path) && Binary->sections().empty())
        {
            Binary = LIEF::ELF::Parser::parse(Path);
        }

        if(!Binary)
        {
            return GtirbBuilder::build_error::ParseError;
        }

        // Build GTIRB from supported binary object formats.
        switch(Binary->format())
        {
            case LIEF::Binary::FORMATS::ELF:
            {
                ElfReader Elf(Path, fs::path(Path).filename().string(), Context, IR, Binary);
                Elf.build();
                break;
            }
            case LIEF::Binary::FORMATS::PE:
            {
                PeReader Pe(Path, fs::path(Path).filename().string(), Context, IR, Binary);
                Pe.build();
                break;
            }
            case LIEF::Binary::FORMATS::MACHO:
            case LIEF::Binary::FORMATS::UNKNOWN:
            default:
                return GtirbBuilder::build_error::NotSupported;
        }

        return GTIRB{Context, IR};
    }

    if(ArchiveReader::isAr(Path))
    {
        gtirb::IR* IR = gtirb::IR::Create(*Context);

        try
        {
            ArchiveReader Archive = ArchiveReader::read(Path);

            for(auto& Object : Archive.Files)
            {
                std::vector<uint8_t> ObjectData;
                Archive.readFile(Object, ObjectData);

                std::shared_ptr<LIEF::Binary> Binary{LIEF::Parser::parse(ObjectData)};
                if(!Binary)
                {
                    return GtirbBuilder::build_error::ParseError;
                }

                if(Binary->format() != LIEF::Binary::FORMATS::ELF)
                {
                    return GtirbBuilder::build_error::NotSupported;
                }

                ElfReader Elf(Path, Object.FileName, Context, IR, Binary);
                Elf.build();
            }
        }
        catch(ArchiveReaderException& e)
        {
            std::cerr << std::endl << "ERROR: " << e.what();
            return GtirbBuilder::build_error::ParseError;
        }

        return GTIRB{Context, IR};
    }

    // Load an existing GTIRB file.
    std::ifstream Stream(Path, std::ios::in | std::ios::binary);
    if(gtirb::ErrorOr<gtirb::IR*> Result = gtirb::IR::load(*Context, Stream))
    {
        return GTIRB{Context, *Result};
    }

    return GtirbBuilder::build_error::NotSupported;
}

GtirbBuilder::GtirbBuilder(std::string P, std::string Name, std::shared_ptr<gtirb::Context> Context,
                           gtirb::IR* IR, std::shared_ptr<LIEF::Binary> B)
    : Path(P), Context(Context), IR(IR), Binary(B)
{
    Module = gtirb::Module::Create(*Context, Name);
    IR->addModule(Module);
}

void GtirbBuilder::build()
{
    initModule();
    buildSections();
    buildSymbols();
    addEntryBlock();
    addAuxData();
}

void GtirbBuilder::initModule()
{
    Module->setBinaryPath(Path);
    Module->setFileFormat(format());
    Module->setISA(isa());
    Module->setByteOrder(endianness());
}

gtirb::ByteOrder GtirbBuilder::endianness()
{
    switch(Binary->header().endianness())
    {
        case LIEF::Header::ENDIANNESS::BIG:
            return gtirb::ByteOrder::Big;
        case LIEF::Header::ENDIANNESS::LITTLE:
            return gtirb::ByteOrder::Little;
        default:
            break;
    }
    return gtirb::ByteOrder::Undefined;
}

gtirb::FileFormat GtirbBuilder::format()
{
    switch(Binary->format())
    {
        case LIEF::Binary::FORMATS::ELF:
            return gtirb::FileFormat::ELF;
        case LIEF::Binary::FORMATS::PE:
            return gtirb::FileFormat::PE;
        default:
            break;
    }
    return gtirb::FileFormat::Undefined;
}

gtirb::ISA GtirbBuilder::isa()
{
    switch(Binary->header().architecture())
    {
        case LIEF::Header::ARCHITECTURES::X86:
            return gtirb::ISA::IA32;
        case LIEF::Header::ARCHITECTURES::X86_64:
            return gtirb::ISA::X64;
        case LIEF::Header::ARCHITECTURES::PPC:
            return gtirb::ISA::PPC32;
        case LIEF::Header::ARCHITECTURES::ARM:
            return gtirb::ISA::ARM;
        case LIEF::Header::ARCHITECTURES::ARM64:
            return gtirb::ISA::ARM64;
        case LIEF::Header::ARCHITECTURES::MIPS:
            return gtirb::ISA::MIPS32;
        case LIEF::Header::ARCHITECTURES::UNKNOWN:
            return gtirb::ISA::Undefined;
        default:
            break;
    }
    return gtirb::ISA::ValidButUnsupported;
}

class GtirbBuildErrorCategory : public std::error_category
{
public:
    const char* name() const noexcept override
    {
        return "GtirbBuilderError";
    }

    std::string message(int Condition) const override
    {
        switch(static_cast<GtirbBuilder::build_error>(Condition))
        {
            case GtirbBuilder::build_error::FileNotFound:
                return "No such file or directory.";
            case GtirbBuilder::build_error::ParseError:
                return "Failed to parse binary.";
            case GtirbBuilder::build_error::NotSupported:
                return "Binary format not supported.";
        }
        assert(false && "Expected to handle all error codes");
        return "";
    }
};

const std::error_category& buildErrorCategory()
{
    static GtirbBuildErrorCategory C;
    return C;
}
