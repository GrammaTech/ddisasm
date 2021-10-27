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

#include <algorithm>
#include <sstream>

ElfReader::ElfReader(std::string Path, std::shared_ptr<LIEF::Binary> Binary)
    : GtirbBuilder(Path, Binary)
{
    Elf = std::dynamic_pointer_cast<LIEF::ELF::Binary>(Binary);
    assert(Elf && "Expected ELF");
};

void ElfReader::buildSections()
{
    std::map<uint64_t, gtirb::UUID> SectionIndex;
    std::map<gtirb::UUID, std::tuple<uint64_t, uint64_t>> SectionProperties;
    std::map<gtirb::UUID, uint64_t> Alignment;

    std::optional<uint64_t> TlsBegin, TlsEnd;
    for(auto &Segment : Elf->segments())
    {
        if(Segment.type() == LIEF::ELF::SEGMENT_TYPES::PT_TLS)
        {
            TlsBegin = Segment.virtual_address();
            TlsEnd = Segment.virtual_address() + Segment.virtual_size();
        }
    }

    uint64_t Index = 0;
    for(auto &Section : Elf->sections())
    {
        bool Loaded = Section.has(LIEF::ELF::ELF_SECTION_FLAGS::SHF_ALLOC);
        bool Executable = Section.has(LIEF::ELF::ELF_SECTION_FLAGS::SHF_EXECINSTR);
        bool Writable = Section.has(LIEF::ELF::ELF_SECTION_FLAGS::SHF_WRITE);
        bool Initialized = Loaded && Section.type() != LIEF::ELF::ELF_SECTION_TYPES::SHT_NOBITS;

        bool Literal = Literals.count(Section.name()) > 0;

        // FIXME: Populate sections that are not loaded (e.g. .symtab and .strtab)
        if(!Loaded && !Literal)
        {
            Index++;
            continue;
        }

        // Add named section to GTIRB Module.
        gtirb::Section *S = Module->addSection(*Context, Section.name());

        // Add section flags to GTIRB Section.
        if(Loaded)
        {
            S->addFlag(gtirb::SectionFlag::Loaded);
            S->addFlag(gtirb::SectionFlag::Readable);
        }
        if(Executable)
        {
            S->addFlag(gtirb::SectionFlag::Executable);
        }
        if(Writable)
        {
            S->addFlag(gtirb::SectionFlag::Writable);
        }
        if(Initialized)
        {
            S->addFlag(gtirb::SectionFlag::Initialized);
        }

        if(Loaded)
        {
            gtirb::Addr Addr = gtirb::Addr(Section.virtual_address());

            // Thread-local data section addresses overlap other sections,
            // as they are only templates for per-thread copies of the data
            // sections.
            bool Tls = Section.has(LIEF::ELF::ELF_SECTION_FLAGS::SHF_TLS);
            if(Tls && TlsBegin && TlsEnd)
            {
                if(Section.virtual_address() >= *TlsBegin && Section.virtual_address() < *TlsEnd)
                {
                    uint64_t Offset = Section.virtual_address() - *TlsBegin;
                    Addr = gtirb::Addr(tlsBaseAddress() + Offset);
                }
                else
                {
                    std::cerr << "WARNING: Failed to rebase TLS section: " << Section.name()
                              << "\n";
                }
            }

            if(Initialized)
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
        }

        if(Literal)
        {
            // Transcribe unloaded, literal data to an address-less section with a single DataBlock.
            std::vector<uint8_t> Bytes = Section.content();
            gtirb::ByteInterval *I = S->addByteInterval(*Context, Bytes.begin(), Bytes.end(),
                                                        Section.size(), Bytes.size());
            I->addBlock<gtirb::DataBlock>(*Context, 0, Section.size());
        }

        // Add section index and raw section properties to aux data.
        Alignment[S->getUUID()] = Section.alignment();
        SectionIndex[Index] = S->getUUID();
        SectionProperties[S->getUUID()] = {static_cast<uint64_t>(Section.type()),
                                           static_cast<uint64_t>(Section.flags())};

        Index++;
    }

    Module->addAuxData<gtirb::schema::Alignment>(std::move(Alignment));
    Module->addAuxData<gtirb::schema::ElfSectionIndex>(std::move(SectionIndex));
    Module->addAuxData<gtirb::schema::ElfSectionProperties>(std::move(SectionProperties));
}

void ElfReader::buildSymbols()
{
    std::map<std::tuple<uint64_t, uint64_t, std::string, std::string, std::string, uint64_t,
                        std::string>,
             std::vector<std::tuple<std::string, uint64_t>>>
        Symbols;
    auto accum_symbol_table = [&](LIEF::ELF::it_symbols SymbolIt, std::string TableName) {
        uint64_t TableIndex = 0;
        for(auto &Symbol : SymbolIt)
        {
            // Skip symbol table sections.
            if(Symbol.type() == LIEF::ELF::ELF_SYMBOL_TYPES::STT_SECTION)
            {
                TableIndex++;
                continue;
            }

            std::string Name = Symbol.name();
            std::optional<std::string> Version;
            if(std::size_t I = Name.find('@'); I != std::string::npos)
            {
                // TODO: Keep track of "default" versions as denoted by double `at'.
                Version = Name.substr(I, 2) == "@@" ? Name.substr(I + 2) : Name.substr(I + 1);
                Name = Name.substr(0, I);
            }
            else if(Symbol.has_version())
            {
                LIEF::ELF::SymbolVersion SymbolVersion = Symbol.symbol_version();
                if(SymbolVersion.has_auxiliary_version())
                {
                    Version = SymbolVersion.symbol_version_auxiliary().name();
                }
            }
            if(Version)
            {
                // Construct a normalized symbol name and a version.
                Name = Name.append("@" + *Version);
            }

            uint64_t Value = Symbol.value();

            // STT_TLS symbols are relative to PT_TLS segment base.
            if(Symbol.type() == LIEF::ELF::ELF_SYMBOL_TYPES::STT_TLS)
            {
                Value = tlsBaseAddress() + Value;
            }

            Symbols[std::tuple(Value, Symbol.size(), LIEF::ELF::to_string(Symbol.type()),
                               LIEF::ELF::to_string(Symbol.binding()),
                               LIEF::ELF::to_string(Symbol.visibility()), Symbol.shndx(), Name)]
                .push_back({TableName, TableIndex});
            TableIndex++;
        }
    };
    accum_symbol_table(Elf->dynamic_symbols(), ".dynsym");
    accum_symbol_table(Elf->static_symbols(), ".symtab");

    std::map<gtirb::UUID, auxdata::ElfSymbolInfo> SymbolInfo;
    std::map<gtirb::UUID, auxdata::ElfSymbolTabIdxInfo> SymbolTabIdxInfo;
    for(auto &[Key, Indexes] : Symbols)
    {
        auto &[Value, Size, Type, Scope, Visibility, SecIndex, Name] = Key;

        gtirb::Symbol *S;

        // Symbols with special section index do not have an address.
        if((SecIndex == static_cast<int>(LIEF::ELF::SYMBOL_SECTION_INDEX::SHN_UNDEF)
            || (SecIndex >= static_cast<int>(LIEF::ELF::SYMBOL_SECTION_INDEX::SHN_LORESERVE)
                && SecIndex <= static_cast<int>(LIEF::ELF::SYMBOL_SECTION_INDEX::SHN_HIRESERVE)))
           && Value == 0)
        {
            S = Module->addSymbol(*Context, Name);
        }
        else
        {
            S = Module->addSymbol(*Context, gtirb::Addr(Value), Name);
        }

        assert(S && "Failed to create symbol.");

        // Add additional symbol information to aux data.
        SymbolInfo[S->getUUID()] = {Size, Type, Scope, Visibility, SecIndex};
        SymbolTabIdxInfo[S->getUUID()] = Indexes;
    }

    Module->addAuxData<gtirb::schema::ElfSymbolInfo>(std::move(SymbolInfo));
    Module->addAuxData<gtirb::schema::ElfSymbolTabIdxInfo>(std::move(SymbolTabIdxInfo));
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
    std::vector<std::string> BinaryType;
    switch(Elf->header().file_type())
    {
        case LIEF::ELF::E_TYPE::ET_DYN:
            BinaryType.emplace_back("DYN");
            break;
        case LIEF::ELF::E_TYPE::ET_EXEC:
            BinaryType.emplace_back("EXEC");
            break;
        default:
            // FIXME: Return an error code here (and wherever else we assert).
            assert(!"Unknown value for ELF file's e_type!");
    }
    Module->addAuxData<gtirb::schema::BinaryType>(std::move(BinaryType));

    // Add `relocations' aux data table.
    std::set<auxdata::ElfRelocation> RelocationTuples;
    for(auto &Relocation : Elf->relocations())
    {
        std::string SymbolName;
        if(Relocation.has_symbol())
        {
            SymbolName = Relocation.symbol().name();

            if(Relocation.symbol().has_version())
            {
                LIEF::ELF::SymbolVersion SymbolVersion = Relocation.symbol().symbol_version();
                if(SymbolVersion.has_auxiliary_version())
                {
                    SymbolName.append("@" + SymbolVersion.symbol_version_auxiliary().name());
                }
            }
        }
        RelocationTuples.insert(
            {Relocation.address(), getRelocationType(Relocation), SymbolName, Relocation.addend()});
    }
    Module->addAuxData<gtirb::schema::Relocations>(std::move(RelocationTuples));

    std::vector<std::string> Libraries = Elf->imported_libraries();
    Module->addAuxData<gtirb::schema::Libraries>(std::move(Libraries));

    std::set<auxdata::ElfDynamicEntry> DynamicEntryTuples;
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
        DynamicEntryTuples.insert({LIEF::ELF::to_string(Entry.tag()), Entry.value()});
    }
    Module->addAuxData<gtirb::schema::LibraryPaths>(std::move(LibraryPaths));
    Module->addAuxData<gtirb::schema::DynamicEntries>(std::move(DynamicEntryTuples));
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

uint64_t ElfReader::tlsBaseAddress()
{
    if(!TlsBaseAddress)
    {
        // Find the largest virtual address.
        uint64_t VirtualEnd = 0;
        for(auto &Segment : Elf->segments())
        {
            VirtualEnd = std::max(VirtualEnd, Segment.virtual_address() + Segment.virtual_size());
        }
        // Use the next available page.
        TlsBaseAddress = (VirtualEnd & ~(0x1000 - 1)) + 0x1000;
    }
    return TlsBaseAddress;
}
