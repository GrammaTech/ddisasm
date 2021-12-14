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
    std::map<gtirb::UUID, uint64_t> Alignment;
    std::map<uint64_t, gtirb::UUID> SectionIndex;
    std::map<gtirb::UUID, std::tuple<uint64_t, uint64_t>> SectionProperties;

    std::optional<uint64_t> TlsBegin, TlsEnd;
    for(auto &Segment : Elf->segments())
    {
        if(Segment.type() == LIEF::ELF::SEGMENT_TYPES::PT_TLS)
        {
            TlsBegin = Segment.virtual_address();
            TlsEnd = Segment.virtual_address() + Segment.virtual_size();
        }
    }

    // ELF object files do not have allocated address spaces.
    if(Elf->header().file_type() == LIEF::ELF::E_TYPE::ET_REL)
    {
        relocateSections();
    }

    uint64_t Index = 0;
    for(auto &Section : Elf->sections())
    {
        bool Loaded = Section.has(LIEF::ELF::ELF_SECTION_FLAGS::SHF_ALLOC);
        bool Executable = Section.has(LIEF::ELF::ELF_SECTION_FLAGS::SHF_EXECINSTR);
        bool Writable = Section.has(LIEF::ELF::ELF_SECTION_FLAGS::SHF_WRITE);
        bool Initialized = Loaded && Section.type() != LIEF::ELF::ELF_SECTION_TYPES::SHT_NOBITS;
        bool Tls = Section.has(LIEF::ELF::ELF_SECTION_FLAGS::SHF_TLS);
        bool Literal = Literals.count(Section.name()) > 0;
        bool Relocatable = Loaded && Section.virtual_address() == 0
                           && Elf->header().file_type() == LIEF::ELF::E_TYPE::ET_REL;

        // FIXME: Populate sections that are not loaded (e.g. .symtab and .strtab)
        if(!Loaded && !Literal)
        {
            Index++;
            continue;
        }

        // Skip empty sections in relocatable ELFs (object files).
        if(Relocatable && Section.size() == 0)
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

            if(Relocatable)
            {
                Addr = gtirb::Addr(SectionRelocations[Section.name()]);
            }

            // Rebase TLS section. Thread-local data section addresses overlap other sections, as
            // they are only templates for per-thread copies of the data sections.
            if(Tls && TlsBegin && TlsEnd && !Relocatable)
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

    auto LoadSymbols = [&](LIEF::ELF::it_symbols SymbolIt, std::string TableName) {
        uint64_t TableIndex = 0;
        for(auto &Symbol : SymbolIt)
        {
            std::string Name = Symbol.name();
            uint64_t Value = Symbol.value();

            // Append the GNU symbol version to the symbol name.
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

            // Rebase symbols onto their respective relocated section address.
            bool Relocatable = Elf->header().file_type() == LIEF::ELF::E_TYPE::ET_REL;
            if(Relocatable)
            {
                if(Symbol.shndx() > 0 && Symbol.shndx() < Elf->sections().size())
                {
                    const LIEF::ELF::Section &Section = Elf->sections()[Symbol.shndx()];
                    Value = SectionRelocations[Section.name()] + Value;
                }
            }

            // Rebase a TLS symbol onto the relocated TLS segment.
            bool Tls = Symbol.type() == LIEF::ELF::ELF_SYMBOL_TYPES::STT_TLS;
            if(Tls && !Relocatable)
            {
                // STT_TLS symbols are relative to PT_TLS segment base.
                Value = tlsBaseAddress() + Value;
            }

            Symbols[std::tuple(Value,                                     // Value
                               Symbol.size(),                             // Size
                               LIEF::ELF::to_string(Symbol.type()),       // Type
                               LIEF::ELF::to_string(Symbol.binding()),    // Binding
                               LIEF::ELF::to_string(Symbol.visibility()), // Scope
                               Symbol.shndx(),                            // Section Index
                               Name                                       // Name(@Version)
                               )]
                .push_back({TableName, TableIndex});
            TableIndex++;
        }
    };

    LoadSymbols(Elf->dynamic_symbols(), ".dynsym");
    LoadSymbols(Elf->static_symbols(), ".symtab");

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
        case LIEF::ELF::E_TYPE::ET_REL:
            BinaryType.emplace_back("REL");
            break;
        default:
            std::cerr << "ERROR: Unsupported ELF file type (e_type): "
                      << LIEF::ELF::to_string(Elf->header().file_type()) << "\n";
            std::exit(EXIT_FAILURE);
    }
    Module->addAuxData<gtirb::schema::BinaryType>(std::move(BinaryType));

    // Add `relocations' aux data table.
    std::set<auxdata::Relocation> RelocationTuples;
    for(auto &Relocation : Elf->relocations())
    {
        std::string SymbolName;
        std::string SectionName;
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

            if(Relocation.has_section())
            {
                LIEF::ELF::Section &Section = Relocation.section();
                SectionName = Section.name();
            }
        }

        uint64_t Address = Relocation.address();
        if(Elf->header().file_type() == LIEF::ELF::E_TYPE::ET_REL
           && Relocation.purpose() == LIEF::ELF::RELOCATION_PURPOSES::RELOC_PURPOSE_OBJECT)
        {
            // Rebase relocation offset for object-file relocations.
            if(Relocation.has_section())
            {
                Address = SectionRelocations[Relocation.section().name()] + Address;
            }
        }

        // RELA relocations have an explicit addend field, and REL relocations store an
        // implicit addend in the location to be modified.
        std::string RelType = Relocation.is_rela() ? "RELA" : "REL";

        RelocationTuples.insert({Address, getRelocationType(Relocation), SymbolName,
                                 Relocation.addend(), Relocation.info(), SectionName, RelType});
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

void ElfReader::relocateSections()
{
    struct AddressRange
    {
        std::string Name;
        uint64_t Align;
        std::pair<uint64_t, uint64_t> Range;

        bool operator<(const AddressRange &Other) const
        {
            return Range < Other.Range;
        }
    };

    struct Disjunct
    {
        bool operator()(AddressRange Lhs, AddressRange Rhs) const
        {
            return std::get<1>(Lhs.Range) <= std::get<0>(Rhs.Range);
        };
    };

    // Begin with a sorted set of offset intervals.
    std::multiset<AddressRange> Offsets;
    for(const auto &S : Elf->sections())
    {
        if(S.virtual_address() == 0 && S.size() > 0
           && S.has(LIEF::ELF::ELF_SECTION_FLAGS::SHF_ALLOC))
        {
            uint64_t Start = S.offset() - Elf->header().header_size();
            uint64_t End = Start + S.size();
            Offsets.insert({S.name(), S.alignment(), {Start, End}});
        }
    }

    // Compose a set of disjunct address ranges from the sorted offset intervals.
    std::multiset<AddressRange, Disjunct> Addresses;

    // Place non-overlapping sections.
    uint64_t NextOffset = 0;
    for(auto It = Offsets.begin(); It != Offsets.end();)
    {
        auto [Start, End] = It->Range;
        if(NextOffset <= Start)
        {
            // Allocate non-overlapping address range.
            Addresses.insert(*It);
            It = Offsets.erase(It);
            NextOffset = End;
        }
        else
        {
            // Skip overlapping section.
            It++;
        }
    }

    // Place remaining overlapping sections in allocation gaps.
    for(auto [Name, Align, Range] : Offsets)
    {
        auto [Start, End] = Range;
        uint64_t Size = End - Start;
        Align = std::max(uint64_t(8), Align);

        AddressRange Relocated = {Name, Align, Range};

        for(auto Prev = Addresses.begin(); Prev != Addresses.end(); Prev++)
        {
            // Align with previous section.
            Start = (std::get<1>(Prev->Range) + (Align - 1)) & ~(Align - 1);
            End = Start + Size;
            Relocated.Range = {Start, End};

            // Peek next element.
            auto Next = Prev;
            Next++;

            if(Next == Addresses.end() || End <= std::get<0>(Next->Range))
            {
                // Fits between previous and next section.
                Addresses.insert(Relocated);
                break;
            }
        }
    }

    for(const AddressRange &Range : Addresses)
    {
        SectionRelocations[Range.Name] = std::get<0>(Range.Range);
    }
}
