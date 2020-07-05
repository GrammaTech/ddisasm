//===- ElfReader.cpp --------------------------------------------*- C++ -*-===//
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

#include "ElfReader.h"

ElfReader::ElfReader(std::string Path, std::shared_ptr<LIEF::Binary> Binary)
    : GtirbBuilder(Path, Binary)
{
    Elf = std::dynamic_pointer_cast<LIEF::ELF::Binary>(Binary);
    assert(Elf && "Expected ELF");
};

void ElfReader::buildSections()
{
    std::map<uint64_t, gtirb::UUID> SectionIndex;
    std::map<gtirb::UUID, SectionProperties> SectionProperties;

    uint64_t Index = 0;
    for(auto &Section : Elf->sections())
    {
        bool is_allocated = Section.has(LIEF::ELF::ELF_SECTION_FLAGS::SHF_ALLOC);
        bool is_executable = Section.has(LIEF::ELF::ELF_SECTION_FLAGS::SHF_EXECINSTR);
        bool is_writable = Section.has(LIEF::ELF::ELF_SECTION_FLAGS::SHF_WRITE);
        // SHT_NOBITS is not considered here because it is for data sections but
        // without initial data (zero initialized)
        bool is_non_zero_program_data =
            Section.type() == LIEF::ELF::ELF_SECTION_TYPES::SHT_PROGBITS
            || Section.type() == LIEF::ELF::ELF_SECTION_TYPES::SHT_INIT_ARRAY
            || Section.type() == LIEF::ELF::ELF_SECTION_TYPES::SHT_FINI_ARRAY
            || Section.type() == LIEF::ELF::ELF_SECTION_TYPES::SHT_PREINIT_ARRAY;
        bool is_initialized = is_allocated && is_non_zero_program_data;
        // TODO: Move .tbss section
        bool is_tls = Section.has(LIEF::ELF::ELF_SECTION_FLAGS::SHF_TLS);

        // Skip sections that are not loaded into memory.
        if(!is_allocated || is_tls)
        {
            Index++;
            continue;
        }

        // Add named section to GTIRB Module.
        gtirb::Section *S = Module->addSection(*Context, Section.name());

        // Add section flags to GTIRB Section.
        if(is_allocated)
        {
            S->addFlag(gtirb::SectionFlag::Loaded);
            S->addFlag(gtirb::SectionFlag::Readable);
        }
        if(is_executable)
        {
            S->addFlag(gtirb::SectionFlag::Executable);
        }
        if(is_writable)
        {
            S->addFlag(gtirb::SectionFlag::Writable);
        }
        if(is_initialized)
        {
            S->addFlag(gtirb::SectionFlag::Initialized);
        }

        gtirb::Addr Addr = gtirb::Addr(Section.virtual_address());
        if(is_initialized)
        {
            // Add allocated section contents to a single, contiguous ByteInterval.
            std::vector<uint8_t> Bytes = Section.content();
            S->addByteInterval(*Context, Addr, Bytes.begin(), Bytes.end(), Section.size(),
                               Bytes.size());
        }
        else
        {
            // Add an uninitialized section.
            S->addByteInterval(*Context, Addr, Section.size(), 0);
        }

        // Add section index and raw section properties to aux data.
        SectionIndex[Index] = S->getUUID();
        SectionProperties[S->getUUID()] = {static_cast<uint64_t>(Section.type()),
                                           static_cast<uint64_t>(Section.flags())};

        Index++;
    }

    Module->addAuxData<gtirb::schema::ElfSectionIndex>(std::move(SectionIndex));
    Module->addAuxData<gtirb::schema::ElfSectionProperties>(std::move(SectionProperties));
}

void ElfReader::buildSymbols()
{
    std::set<std::tuple<uint64_t, uint64_t, std::string, std::string, std::string, uint64_t,
                        std::string>>
        Symbols;
    for(auto &Symbol : Elf->symbols())
    {
        // Skip symbol table sections.
        if(Symbol.type() == LIEF::ELF::ELF_SYMBOL_TYPES::STT_SECTION)
        {
            continue;
        }

        // Remove version suffix from symbol name.
        std::string Name = Symbol.name();
        std::size_t Version = Name.find('@');
        if(Version != std::string::npos)
        {
            Name = Name.substr(0, Version);
        }

        Symbols.insert({
            Symbol.value(),
            Symbol.size(),
            LIEF::ELF::to_string(Symbol.type()),
            LIEF::ELF::to_string(Symbol.binding()),
            LIEF::ELF::to_string(Symbol.visibility()),
            Symbol.shndx(),
            Name,
        });
    }

    std::map<gtirb::UUID, ElfSymbolInfo> SymbolInfo;
    for(auto &[Value, Size, Type, Scope, Visibility, Index, Name] : Symbols)
    {
        gtirb::Symbol *S;

        // Symbols with special section index do not have an address.
        if(Index == static_cast<int>(LIEF::ELF::SYMBOL_SECTION_INDEX::SHN_UNDEF)
           || (Index >= static_cast<int>(LIEF::ELF::SYMBOL_SECTION_INDEX::SHN_LORESERVE)
               && Index <= static_cast<int>(LIEF::ELF::SYMBOL_SECTION_INDEX::SHN_HIRESERVE)))
        {
            S = Module->addSymbol(*Context, Name);
        }
        else
        {
            S = Module->addSymbol(*Context, gtirb::Addr(Value), Name);
        }

        assert(S && "Failed to create symbol.");

        // Add additional symbol information to aux data.
        SymbolInfo[S->getUUID()] = {Size, Type, Scope, Visibility, Index};
    }
    Module->addAuxData<gtirb::schema::ElfSymbolInfoAD>(std::move(SymbolInfo));
}

void ElfReader::addEntryBlock()
{
    gtirb::Addr Entry = gtirb::Addr(Elf->entrypoint());
    if(auto It = Module->findByteIntervalsOn(Entry); !It.empty())
    {
        if(gtirb::ByteInterval &Interval = *It.begin(); Interval.getAddress())
        {
            uint64_t Offset = Entry - *Interval.getAddress();
            gtirb::CodeBlock *Block = Interval.addBlock<gtirb::CodeBlock>(*Context, Offset, 0);
            Module->setEntryPoint(Block);
        }
    }
    assert(Module->getEntryPoint() && "Failed to set module entry point.");
}

void ElfReader::addAuxData()
{
    // Add `binaryType' aux data table.
    std::vector<std::string> BinaryType = {Elf->is_pie() ? "DYN" : "EXEC"};
    Module->addAuxData<gtirb::schema::BinaryType>(std::move(BinaryType));

    // Add `relocations' aux data table.
    std::set<ElfRelocation> RelocationTuples;
    for(auto &Relocation : Elf->relocations())
    {
        std::string SymbolName;
        if(Relocation.has_symbol())
        {
            SymbolName = Relocation.symbol().name();
        }
        RelocationTuples.insert(
            {Relocation.address(), getRelocationType(Relocation), SymbolName, Relocation.addend()});
    }
    Module->addAuxData<gtirb::schema::Relocations>(std::move(RelocationTuples));

    std::vector<std::string> Libraries = Elf->imported_libraries();
    Module->addAuxData<gtirb::schema::Libraries>(std::move(Libraries));

    std::vector<std::string> LibraryPaths;
    for(const auto &Entry : Elf->dynamic_entries())
    {
        if(const auto RunPath = dynamic_cast<const LIEF::ELF::DynamicEntryRunPath *>(&Entry))
        {
            std::vector<std::string> Paths = RunPath->paths();
            LibraryPaths.insert(LibraryPaths.end(), Paths.begin(), Paths.end());
        }
        if(const auto Rpath = dynamic_cast<const LIEF::ELF::DynamicEntryRpath *>(&Entry))
        {
            std::vector<std::string> Paths = Rpath->paths();
            LibraryPaths.insert(LibraryPaths.end(), Paths.begin(), Paths.end());
        }
    }
    Module->addAuxData<gtirb::schema::LibraryPaths>(std::move(LibraryPaths));
}

std::string ElfReader::getRelocationType(const LIEF::ELF::Relocation &Entry)
{
    switch(Entry.architecture())
    {
        case LIEF::ELF::ARCH::EM_X86_64:
            return LIEF::ELF::to_string(static_cast<LIEF::ELF::RELOC_x86_64>(Entry.type()));
        case LIEF::ELF::ARCH::EM_386:
            return LIEF::ELF::to_string(static_cast<LIEF::ELF::RELOC_i386>(Entry.type()));
        case LIEF::ELF::ARCH::EM_ARM:
            return LIEF::ELF::to_string(static_cast<LIEF::ELF::RELOC_ARM>(Entry.type()));
        case LIEF::ELF::ARCH::EM_AARCH64:
            return LIEF::ELF::to_string(static_cast<LIEF::ELF::RELOC_AARCH64>(Entry.type()));
        case LIEF::ELF::ARCH::EM_PPC:
            return LIEF::ELF::to_string(static_cast<LIEF::ELF::RELOC_POWERPC32>(Entry.type()));
        case LIEF::ELF::ARCH::EM_PPC64:
            return LIEF::ELF::to_string(static_cast<LIEF::ELF::RELOC_POWERPC64>(Entry.type()));
        default:
            return std::to_string(Entry.type());
    }
}
