//===- LIEFBinaryReader.cpp ------------------------------------------*- C++ -*-===//
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

#include "LIEFBinaryReader.h"

LIEFBinaryReader::LIEFBinaryReader(const std::string& filename)
{
    bin = LIEF::Parser::parse(filename);
}

bool LIEFBinaryReader::is_valid()
{
    return bin->format() == LIEF::EXE_FORMATS::FORMAT_ELF
           || bin->format() == LIEF::EXE_FORMATS::FORMAT_PE;
}

std::optional<std::tuple<std::vector<uint8_t>, uint64_t>>
LIEFBinaryReader::get_section_content_and_address(const std::string& name)
{
    for(auto& section : bin->sections())
    {
        if(section.name() == name)
            return std::make_tuple(section.content(), section.virtual_address());
    }
    return std::nullopt;
}

uint64_t LIEFBinaryReader::get_max_address()
{
    uint64_t max_address = 0;
    if(auto* elf = dynamic_cast<LIEF::ELF::Binary*>(bin.get()))
    {
        for(auto& section : elf->sections())
        {
            if(section.type() == LIEF::ELF::ELF_SECTION_TYPES::SHT_PROGBITS
               || section.type() == LIEF::ELF::ELF_SECTION_TYPES::SHT_NOBITS)
            {
                max_address = std::max(max_address, section.virtual_address() + section.size());
            }
        }
    }

    if(auto* pe = dynamic_cast<LIEF::PE::Binary*>(bin.get()))
    {
        for(auto& section : pe->sections())
        {
            max_address = std::max(max_address, section.virtual_address() + section.size());
        }
    }
    return max_address;
}

uint64_t LIEFBinaryReader::get_min_address()
{
    uint64_t min_address = UINTMAX_MAX;
    if(auto* elf = dynamic_cast<LIEF::ELF::Binary*>(bin.get()))
    {
        for(auto& section : elf->sections())
        {
            if(section.type() == LIEF::ELF::ELF_SECTION_TYPES::SHT_PROGBITS
               || section.type() == LIEF::ELF::ELF_SECTION_TYPES::SHT_NOBITS)
            {
                min_address = std::min(min_address, section.virtual_address());
            }
        }
    }
    if(auto* pe = dynamic_cast<LIEF::PE::Binary*>(bin.get()))
    {
        for(auto& section : pe->sections())
        {
            min_address = std::min(min_address, section.virtual_address());
        }
    }
    return min_address;
}

std::vector<Section> LIEFBinaryReader::get_sections()
{
    std::vector<Section> sectionTuples;
    for(auto& section : bin->sections())
    {
        sectionTuples.push_back({section.name(), section.size(), section.virtual_address()});
    }
    return sectionTuples;
}

std::string LIEFBinaryReader::get_binary_type()
{
    if(bin->is_pie())
        return "DYN";
    return "EXEC";
}

uint64_t LIEFBinaryReader::get_entry_point()
{
    return bin->entrypoint();
}

std::vector<Symbol> LIEFBinaryReader::get_symbols()
{
    std::vector<Symbol> symbolTuples;
    if(auto* elf = dynamic_cast<LIEF::ELF::Binary*>(bin.get()))
    {
        for(auto& symbol : elf->symbols())
        {
            std::string symbolName = symbol.name();
            std::size_t foundVersion = symbolName.find('@');
            if(foundVersion != std::string::npos)
                symbolName = symbolName.substr(0, foundVersion);
            symbolTuples.push_back({symbol.value(), symbol.size(), getSymbolType(symbol.type()),
                                    getSymbolBinding(symbol.binding()), symbol.section_idx(),
                                    symbolName});
        }
    }

    if(auto* pe = dynamic_cast<LIEF::PE::Binary*>(bin.get()))
    {
        for(auto& symbol : pe->symbols())
        {
            std::string symbolName = symbol.name();
            std::size_t foundVersion = symbolName.find('@');
            if(foundVersion != std::string::npos)
                symbolName = symbolName.substr(0, foundVersion);
            // FIXME: do symbols in PE have an equivalent concept?
            symbolTuples.push_back({symbol.value(), symbol.size(), "NOTYPE", "GLOBAL",
                                    static_cast<uint64_t>(symbol.section_number()), symbolName});
        }
    }
    return symbolTuples;
}

std::vector<Relocation> LIEFBinaryReader::get_relocations()
{
    std::vector<Relocation> relocationTuples;
    if(auto* elf = dynamic_cast<LIEF::ELF::Binary*>(bin.get()))
    {
        for(auto& relocation : elf->relocations())
        {
            relocationTuples.push_back({relocation.address(), getRelocationType(relocation.type()),
                                        relocation.symbol().name(), relocation.addend()});
        }
    }
    return relocationTuples;
}

std::vector<std::string> LIEFBinaryReader::get_libraries()
{
    std::vector<std::string> libraries;
    // TODO
    return libraries;
}

std::vector<std::string> LIEFBinaryReader::get_library_paths()
{
    std::vector<std::string> libraryPaths;
    // TODO
    return libraryPaths;
}

std::string LIEFBinaryReader::getSymbolType(LIEF::ELF::ELF_SYMBOL_TYPES type)
{
    switch(type)
    {
        case LIEF::ELF::ELF_SYMBOL_TYPES::STT_NOTYPE:
            return "NOTYPE";
        case LIEF::ELF::ELF_SYMBOL_TYPES::STT_OBJECT:
            return "OBJECT";
        case LIEF::ELF::ELF_SYMBOL_TYPES::STT_FUNC:
            return "FUNC";
        case LIEF::ELF::ELF_SYMBOL_TYPES::STT_SECTION:
            return "SECTION";
        case LIEF::ELF::ELF_SYMBOL_TYPES::STT_FILE:
            return "FILE";
        case LIEF::ELF::ELF_SYMBOL_TYPES::STT_COMMON:
            return "COMMON";
        case LIEF::ELF::ELF_SYMBOL_TYPES::STT_TLS:
            return "TLS";
        default:
            return "OTHER";
    }
}

std::string LIEFBinaryReader::getSymbolBinding(LIEF::ELF::SYMBOL_BINDINGS binding)
{
    switch(binding)
    {
        case LIEF::ELF::SYMBOL_BINDINGS::STB_LOCAL:
            return "LOCAL";
        case LIEF::ELF::SYMBOL_BINDINGS::STB_GLOBAL:
            return "GLOBAL";
        case LIEF::ELF::SYMBOL_BINDINGS::STB_WEAK:
            return "WEAK";
        default:
            return "OTHER";
    }
}
std::string LIEFBinaryReader::getRelocationType(uint32_t type)
{
    static std::string type_names[40] = {
        "R_X86_64_NONE",
        "R_X86_64_64",              /* Direct 64 bit  */
        "R_X86_64_PC32",            /* PC relative 32 bit signed */
        "R_X86_64_GOT32",           /* 32 bit GOT entry */
        "R_X86_64_PLT32",           /* 32 bit PLT address */
        "R_X86_64_COPY",            /* Copy symbol at runtime */
        "R_X86_64_GLOB_DAT",        /* Create GOT entry */
        "R_X86_64_JUMP_SLOT",       /* Create PLT entry */
        "R_X86_64_RELATIVE",        /* Adjust by program base */
        "R_X86_64_GOTPCREL",        /* 32 bit signed PC relative
   offset to GOT */
        "R_X86_64_32",              /* Direct 32 bit zero extended */
        "R_X86_64_32S",             /* Direct 32 bit sign extended */
        "R_X86_64_16",              /* Direct 16 bit zero extended */
        "R_X86_64_PC16",            /* 16 bit sign extended pc relative */
        "R_X86_64_8",               /* Direct 8 bit sign extended  */
        "R_X86_64_PC8",             /* 8 bit sign extended pc relative */
        "R_X86_64_DTPMOD64",        /* ID of module containing symbol */
        "R_X86_64_DTPOFF64",        /* Offset in module's TLS block */
        "R_X86_64_TPOFF64",         /* Offset in initial TLS block */
        "R_X86_64_TLSGD",           /* 32 bit signed PC relative offset
                 to two GOT entries for GD symbol */
        "R_X86_64_TLSLD",           /* 32 bit signed PC relative offset
       to two GOT entries for LD symbol */
        "R_X86_64_DTPOFF32",        /* Offset in TLS block */
        "R_X86_64_GOTTPOFF",        /* 32 bit signed PC relative offset
   to GOT entry for IE symbol */
        "R_X86_64_TPOFF32",         /* Offset in initial TLS block */
        "R_X86_64_PC64",            /* PC relative 64 bit */
        "R_X86_64_GOTOFF64",        /* 64 bit offset to GOT */
        "R_X86_64_GOTPC32",         /* 32 bit signed pc relative
   offset to GOT */
        "R_X86_64_GOT64",           /* 64-bit GOT entry offset */
        "R_X86_64_GOTPCREL64",      /* 64-bit PC relative offset
    to GOT entry */
        "R_X86_64_GOTPC64",         /* 64-bit PC relative offset to GOT */
        "R_X86_64_GOTPLT64",        /* like GOT64, says PLT entry needed */
        "R_X86_64_PLTOFF64",        /* 64-bit GOT relative offset
      to PLT entry */
        "R_X86_64_SIZE32",          /* Size of symbol plus 32-bit addend */
        "R_X86_64_SIZE64",          /* Size of symbol plus 64-bit addend */
        "R_X86_64_GOTPC32_TLSDESC", /* GOT offset for TLS descriptor.  */
        "R_X86_64_TLSDESC_CALL",    /* Marker for call through TLS
descriptor.  */
        "R_X86_64_TLSDESC",         /* TLS descriptor.  */
        "R_X86_64_IRELATIVE",       /* Adjust indirectly by program base */
        "R_X86_64_RELATIVE64",      /* 64-bit adjust by program base */
        "R_X86_64_NUM"};
    if(type < 40)
        return type_names[type];
    return "UNKNOWN";
}
