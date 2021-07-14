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

    // Parse an input binary with LIEF.
    if(LIEF::ELF::is_elf(Path) || LIEF::PE::is_pe(Path))
    {
        std::shared_ptr<LIEF::Binary> Binary{LIEF::Parser::parse(Path)};
        if(!Binary)
        {
            return GtirbBuilder::build_error::ParseError;
        }

        // Build GTIRB from supported binary object formats.
        switch(Binary->format())
        {
            case LIEF::EXE_FORMATS::FORMAT_ELF:
            {
                ElfReader Elf(Path, Binary);
                return Elf.build();
            }
            case LIEF::EXE_FORMATS::FORMAT_PE:
            {
                PeReader Pe(Path, Binary);
                return Pe.build();
            }
            case LIEF::EXE_FORMATS::FORMAT_MACHO:
            case LIEF::EXE_FORMATS::FORMAT_UNKNOWN:
                break;
        }
    }

    // Load an existing GTIRB file.
    auto Context = std::make_unique<gtirb::Context>();
    std::ifstream Stream(Path, std::ios::in | std::ios::binary);
    if(gtirb::ErrorOr<gtirb::IR*> Result = gtirb::IR::load(*Context, Stream))
    {
        return GTIRB{std::move(Context), *Result};
    }

    return GtirbBuilder::build_error::NotSupported;
}

GtirbBuilder::GtirbBuilder(std::string P, std::shared_ptr<LIEF::Binary> B) : Path(P), Binary(B)
{
    Context = std::make_unique<gtirb::Context>();
    IR = gtirb::IR::Create(*Context);
    Module = gtirb::Module::Create(*Context, Binary->name());
    IR->addModule(Module);
}

gtirb::ErrorOr<GTIRB> GtirbBuilder::build()
{
    initModule();
    buildSections();
    buildSymbols();
    addEntryBlock();
    addAuxData();
    return GTIRB{std::move(Context), IR};
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
        case LIEF::ENDIANNESS::ENDIAN_BIG:
            return gtirb::ByteOrder::Big;
        case LIEF::ENDIANNESS::ENDIAN_LITTLE:
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
        case LIEF::EXE_FORMATS::FORMAT_ELF:
            return gtirb::FileFormat::ELF;
        case LIEF::EXE_FORMATS::FORMAT_PE:
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
        case LIEF::ARCHITECTURES::ARCH_X86:
            if(Binary->header().is_32())
                return gtirb::ISA::IA32;
            else
                return gtirb::ISA::X64;
        case LIEF::ARCHITECTURES::ARCH_PPC:
            return gtirb::ISA::PPC32;
        case LIEF::ARCHITECTURES::ARCH_ARM:
            return gtirb::ISA::ARM;
        case LIEF::ARCHITECTURES::ARCH_ARM64:
            return gtirb::ISA::ARM64;
        case LIEF::ARCHITECTURES::ARCH_NONE:
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
