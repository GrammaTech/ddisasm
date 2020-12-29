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

// FIXME: LIEF returns LIEF::ARCHITECTURES::ARCH_NONE for MIPS, which should be
// reported and fixed. For now, we just fix it up after the
void ElfReader::initModule()
{
    GtirbBuilder::initModule();
    switch(Elf->header().machine_type())
    {
        case LIEF::ELF::ARCH::EM_MIPS:
            Module->setISA(gtirb::ISA::MIPS32);
    }
}

// Resurrect sections and symbols from sectionless binary
void ElfReader::resurrectSectionsAndSymbols()
{
    std::map<uint64_t, gtirb::UUID> SectionIndex;
    std::map<gtirb::UUID, SectionProperties> SectionProperties;
    std::map<gtirb::UUID, uint64_t> Alignment;

    // Collect dynamic entries
    std::map<std::string, uint64_t> dynamicEntries;
    for(const auto &Entry : Elf->dynamic_entries())
    {
        std::string entry = LIEF::ELF::to_string(Entry.tag());
        uint64_t value = Entry.value();
        dynamicEntries[entry] = value;
    }

    // Collect loaded segments ---------------------------------------
    // TODO: This assumes there is one segment for RW and one for RX.
    LIEF::ELF::Segment LoadedSegmentRW; // for .got and .bss
    LIEF::ELF::Segment LoadedSegmentRX; // for fake executable section
    for(auto &Segment : Elf->segments())
    {
        if(Segment.type() == LIEF::ELF::SEGMENT_TYPES::PT_LOAD)
        {
            if(Segment.has(LIEF::ELF::ELF_SEGMENT_FLAGS::PF_X))
            {
                // Check if there's multiple LoadedSegmentRX
                assert((LoadedSegmentRX.physical_size() == 0)
                       && "Developer Assert: Multiple RX segments found");
                LoadedSegmentRX = Segment;
            }
            else
            {
                // Check if there's multiple LoadedSegmentRW
                assert((LoadedSegmentRW.physical_size() == 0)
                       && "Developer Assert: Multiple RW segments found");
                LoadedSegmentRW = Segment;
            }
        }
    }

    uint64_t Index = 0;

    // Create .fake.ex.segment ---------------------------------------
    {
        auto Segment = LoadedSegmentRX;
        uint64_t addr = Segment.virtual_address();
        uint64_t size = Segment.virtual_size();

        // Add named section to GTIRB Module.
        gtirb::Section *S = Module->addSection(*Context, ".fake.ex.segment");
        // Add section flags to GTIRB Section.
        S->addFlag(gtirb::SectionFlag::Loaded);
        S->addFlag(gtirb::SectionFlag::Readable);
        S->addFlag(gtirb::SectionFlag::Executable);
        S->addFlag(gtirb::SectionFlag::Writable);
        S->addFlag(gtirb::SectionFlag::Initialized);

        gtirb::Addr Addr = gtirb::Addr(addr);
        std::vector<uint8_t> Bytes = Elf->get_content_from_virtual_address(addr, size);
        S->addByteInterval(*Context, Addr, Bytes.begin(), Bytes.end(), size, Bytes.size());

        uint64_t type = static_cast<uint64_t>(Segment.type())
                        | static_cast<uint64_t>(LIEF::ELF::ELF_SECTION_TYPES::SHT_PROGBITS);
        uint64_t flags = static_cast<uint64_t>(Segment.flags())
                         | static_cast<uint64_t>(LIEF::ELF::ELF_SECTION_FLAGS::SHF_ALLOC)
                         | static_cast<uint64_t>(LIEF::ELF::ELF_SECTION_FLAGS::SHF_WRITE);

        Alignment[S->getUUID()] = 16;
        SectionIndex[Index] = S->getUUID();
        SectionProperties[S->getUUID()] = {type, flags};
        ++Index;
    }

    // Create .got ---------------------------------------------------
    uint64_t got_addr = 0;
    uint64_t got_size = 0;
    uint64_t bss_distance = 0; // offset of bss in LoadedSegmentRW
    {
        auto Segment = LoadedSegmentRW;
        uint64_t addr = Segment.virtual_address();
        uint64_t size = Segment.virtual_size();

        // Add named section to GTIRB Module.
        gtirb::Section *S = Module->addSection(*Context, ".got");
        // Add section flags to GTIRB Section.
        S->addFlag(gtirb::SectionFlag::Loaded);
        S->addFlag(gtirb::SectionFlag::Readable);
        S->addFlag(gtirb::SectionFlag::Writable);
        S->addFlag(gtirb::SectionFlag::Initialized);

        uint64_t type = static_cast<uint64_t>(LIEF::ELF::ELF_SECTION_TYPES::SHT_PROGBITS);
        uint64_t flags = static_cast<uint64_t>(LIEF::ELF::ELF_SECTION_FLAGS::SHF_ALLOC
                                               | LIEF::ELF::ELF_SECTION_FLAGS::SHF_WRITE);

        auto it = dynamicEntries.find("PLTGOT");
        assert((it != dynamicEntries.end()) && "PLTGOT not found");
        got_addr = it->second;
        got_size = size - (got_addr - addr);

        std::vector<uint8_t> Bytes = Elf->get_content_from_virtual_address(got_addr, got_size);
        std::vector<uint8_t> BytesCopy = Bytes;
        std::reverse(BytesCopy.begin(), BytesCopy.end());
        uint64_t bss_rdistance = std::distance(
            BytesCopy.begin(),
            find_if(BytesCopy.begin(), BytesCopy.end(), [](auto x) { return x != 0; }));
        bss_distance = BytesCopy.size() - bss_rdistance;

        gtirb::Addr Addr = gtirb::Addr(got_addr);
        S->addByteInterval(*Context, Addr, Bytes.begin(), Bytes.end(), bss_distance,
                           Bytes.size() - bss_rdistance);

        Alignment[S->getUUID()] = 16;
        SectionIndex[Index] = S->getUUID();
        SectionProperties[S->getUUID()] = {type, flags};
        ++Index;
    }

    // Create .bss section if there's any in LoadedSegmentRW ---------
    if(got_addr != 0 && got_size != 0)
    {
        // Find the first address starting consecutive zeros,
        // which is highly likely .bss
        std::vector<uint8_t> Bytes = Elf->get_content_from_virtual_address(got_addr, got_size);
        if(bss_distance >= 0 && bss_distance < Bytes.size())
        {
            uint64_t BssAddr = got_addr + bss_distance;
            uint64_t BssSize = Bytes.size() - bss_distance;

            gtirb::Section *Bss = Module->addSection(*Context, ".bss");
            // Add section flags to GTIRB Section.
            Bss->addFlag(gtirb::SectionFlag::Loaded);
            Bss->addFlag(gtirb::SectionFlag::Readable);
            Bss->addFlag(gtirb::SectionFlag::Writable);
            Bss->addByteInterval(*Context, gtirb::Addr(BssAddr), Bytes.begin() + bss_distance,
                                 Bytes.end(), got_size - bss_distance, BssSize);

            Alignment[Bss->getUUID()] = 16;
            SectionIndex[Index] = Bss->getUUID();
            SectionProperties[Bss->getUUID()] = {
                static_cast<uint64_t>(LIEF::ELF::ELF_SECTION_TYPES::SHT_PROGBITS),
                static_cast<uint64_t>(LIEF::ELF::ELF_SECTION_FLAGS::SHF_ALLOC
                                      | LIEF::ELF::ELF_SECTION_FLAGS::SHF_WRITE)};

            ++Index;
        }
    }

    Module->addAuxData<gtirb::schema::Alignment>(std::move(Alignment));
    Module->addAuxData<gtirb::schema::ElfSectionIndex>(std::move(SectionIndex));
    Module->addAuxData<gtirb::schema::ElfSectionProperties>(std::move(SectionProperties));

    // Extract bytes from STRTAB -------------------------------------
    std::vector<uint8_t> strtabBytes;
    auto it = dynamicEntries.find("STRTAB");
    if(it != dynamicEntries.end())
    {
        uint64_t strtab_addr = it->second;
        it = dynamicEntries.find("STRSZ");
        if(it != dynamicEntries.end())
        {
            uint64_t strtab_size = it->second;
            strtabBytes = Elf->get_content_from_virtual_address(strtab_addr, strtab_size);
        }
    }

    // Extract symbols -----------------------------------------------
    // NOTE: The following code is specific to MIPS32.
    if(Module->getISA() == gtirb::ISA::MIPS32)
    {
        auto it = dynamicEntries.find("SYMTAB");
        assert((it != dynamicEntries.end()) && "SYMTAB not found");
        uint64_t addr = it->second;

        it = dynamicEntries.find("MIPS_SYMTABNO");
        assert((it != dynamicEntries.end()) && "MIPS_SYMTABNO not found");
        uint64_t dynsym_num = it->second;

        it = dynamicEntries.find("MIPS_GOTSYM");
        assert((it != dynamicEntries.end()) && "MIPS_GOTSYM not found");
        uint64_t gotsym_index = it->second;

        it = dynamicEntries.find("MIPS_RLD_MAP");
        assert((it != dynamicEntries.end()) && "MIPS_RLD_MAP not found");
        uint64_t rld_map_addr = it->second;

        it = dynamicEntries.find("MIPS_LOCAL_GOTNO");
        assert((it != dynamicEntries.end()) && "MIPS_LOCAL_GOTNO not found");
        uint64_t localno = it->second;

        it = dynamicEntries.find("SYMENT");
        assert((it != dynamicEntries.end()) && "SYMENT not found");
        uint64_t symtab_entry_size = it->second;

        uint64_t size = dynsym_num * symtab_entry_size;

        std::vector<uint8_t> Bytes = Elf->get_content_from_virtual_address(addr, size);

        std::map<std::tuple<uint64_t, uint64_t, uint64_t, std::string, std::string, std::string,
                            uint64_t, std::string>,
                 std::vector<std::tuple<std::string, uint64_t>>>
            Symbols;
        bool found_gp = false;
        uint64_t TableIndex = 0;
        auto iter = Bytes.begin();
        // Get the 4-byte value starting from current 'iter'.
        // NOTE: This is bit-endian data contruction.
        auto get_4bytes = [&]() {
            assert(iter != Bytes.end());
            uint8_t n0 = *iter++;
            assert(iter != Bytes.end());
            uint8_t n1 = *iter++;
            assert(iter != Bytes.end());
            uint8_t n2 = *iter++;
            assert(iter != Bytes.end());
            uint8_t n3 = *iter++;
            uint32_t n = (n0 << 24) + (n1 << 16) + (n2 << 8) + n3;
            return n;
        };
        // Extract a string at the given index in STRTAB
        auto get_string_at = [&strtabBytes](uint32_t index) {
            std::stringstream ss;
            auto it = strtabBytes.begin() + index;
            while(it != strtabBytes.end())
            {
                uint8_t v = *it++;
                if(v == 0)
                    break;
                ss << v;
            }
            return ss.str();
        };

        // Iterate each symbol entry:
        // struct Elf32_Sym {
        //   Elf32_Word    st_name;  /**< Symbol name (index into string table) */
        //   Elf32_Addr    st_value; /**< Value or address associated with the symbol */
        //   Elf32_Word    st_size;  /**< Size of the symbol */
        //   unsigned char st_info;  /**< Symbol's type and binding attributes */
        //   unsigned char st_other; /**< Must be zero; reserved */
        //   Elf32_Half    st_shndx; /**< Which section (header table index) it's defined in */
        //};
        for(uint64_t i = 0; i < dynsym_num; ++i)
        {
            uint64_t Address = rld_map_addr + (i + 1) * 4;

            // st_name
            uint32_t n = get_4bytes();
            std::string Name = get_string_at(n);

            // Remove version suffix from symbol name.
            std::size_t Version = Name.find('@');
            if(Version != std::string::npos)
            {
                Name = Name.substr(0, Version);
            }
            if(Name == "_gp")
            {
                found_gp = true;
            }

            // st_value
            uint32_t Value = get_4bytes();

            // st_size
            uint32_t s = get_4bytes();
            // NOTE: s is 0 here. For now, use 4 for all symbols.

            // st_info
            uint8_t i0 = *iter++;
            uint8_t type = i0 & 15;
            uint8_t binding = (i0 >> 4) & 15;

            // st_other
            uint8_t o0 = *iter++;

            // st_shndx
            uint8_t sh0 = *iter++;
            uint8_t sh1 = *iter++;
            uint32_t Shndx = (sh0 << 8) + sh1;

            // Skip symbol table sections.
            if((LIEF::ELF::ELF_SYMBOL_TYPES)type == LIEF::ELF::ELF_SYMBOL_TYPES::STT_SECTION)
            {
                TableIndex++;
                continue;
            }

            Symbols[std::tuple(
                        Address, Value, 4, LIEF::ELF::to_string((LIEF::ELF::ELF_SYMBOL_TYPES)type),
                        LIEF::ELF::to_string((LIEF::ELF::SYMBOL_BINDINGS)binding),
                        LIEF::ELF::to_string((LIEF::ELF::ELF_SYMBOL_VISIBILITY)0), Shndx, Name)]
                .push_back({".dynsym", TableIndex});
            TableIndex++;
        }

        // If _gp is not found, create one.
        if(!found_gp)
        {
            Symbols[std::tuple(rld_map_addr + 0x8000, rld_map_addr + 0x8000, 0,
                               LIEF::ELF::to_string(LIEF::ELF::ELF_SYMBOL_TYPES::STT_NOTYPE),
                               LIEF::ELF::to_string(LIEF::ELF::SYMBOL_BINDINGS::STB_LOCAL),
                               LIEF::ELF::to_string((LIEF::ELF::ELF_SYMBOL_VISIBILITY)0), 0, "_gp")]
                .push_back({".symtab", 0});
            TableIndex++;
        }

        // Create gtirb symbols for the collected symbol entries.
        std::map<gtirb::UUID, ElfSymbolInfo> SymbolInfo;
        std::map<gtirb::UUID, ElfSymbolTabIdxInfo> SymbolTabIdxInfo;
        for(auto &[Key, Indexes] : Symbols)
        {
            auto &[Address, Value, Size, Type, Scope, Visibility, SecIndex, Name] = Key;

            gtirb::Symbol *S;

            // Symbols with special section index do not have an address.
            if((SecIndex == static_cast<int>(LIEF::ELF::SYMBOL_SECTION_INDEX::SHN_UNDEF)
                || (SecIndex >= static_cast<int>(LIEF::ELF::SYMBOL_SECTION_INDEX::SHN_LORESERVE)
                    && SecIndex
                           <= static_cast<int>(LIEF::ELF::SYMBOL_SECTION_INDEX::SHN_HIRESERVE)))
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
        if(!SymbolInfo.empty())
        {
            Module->addAuxData<gtirb::schema::ElfSymbolInfoAD>(std::move(SymbolInfo));
        }
        if(!SymbolTabIdxInfo.empty())
        {
            Module->addAuxData<gtirb::schema::ElfSymbolTabIdxInfoAD>(std::move(SymbolTabIdxInfo));
        }
    }
}

void ElfReader::buildSections()
{
    std::map<uint64_t, gtirb::UUID> SectionIndex;
    std::map<gtirb::UUID, SectionProperties> SectionProperties;
    std::map<gtirb::UUID, uint64_t> Alignment;

    // For sectionless binary, call resurrectSectionsAndSymbols.
    if(Elf->sections().size() == 0)
    {
        resurrectSectionsAndSymbols();
        return;
    }

    uint64_t Index = 0;
    for(auto &Section : Elf->sections())
    {
        bool Loaded = Section.has(LIEF::ELF::ELF_SECTION_FLAGS::SHF_ALLOC);
        bool Executable = Section.has(LIEF::ELF::ELF_SECTION_FLAGS::SHF_EXECINSTR);
        bool Writable = Section.has(LIEF::ELF::ELF_SECTION_FLAGS::SHF_WRITE);
        bool Initialized = Loaded && Section.type() != LIEF::ELF::ELF_SECTION_TYPES::SHT_NOBITS;

        // FIXME: Populate sections that are not loaded (e.g. .symtab and .strtab)
        if(!Loaded)
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

        gtirb::Addr Addr = gtirb::Addr(Section.virtual_address());

        // Thread-local data sections overlap other sections, as they are
        // only templates for per-thread copies of the data sections.
        bool Tls = Section.has(LIEF::ELF::ELF_SECTION_FLAGS::SHF_TLS);
        if(Tls)
        {
            Addr = gtirb::Addr(Section.virtual_address() + tlsBaseAddress());
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
    std::optional<uint64_t> Tls;
    for(auto &Segment : Elf->segments())
    {
        if(Segment.type() == LIEF::ELF::SEGMENT_TYPES::PT_TLS)
        {
            Tls = Segment.virtual_address();
        }
    }

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

            // Remove version suffix from symbol name.
            std::string Name = Symbol.name();
            std::size_t Version = Name.find('@');
            if(Version != std::string::npos)
            {
                Name = Name.substr(0, Version);
            }

            uint64_t Value = Symbol.value();

            // STT_TLS symbols are relative to PT_TLS segment base.
            if(Symbol.type() == LIEF::ELF::ELF_SYMBOL_TYPES::STT_TLS)
            {
                assert(Tls && "Found TLS symbol but no TLS segment.");
                Value = *Tls + Value + tlsBaseAddress();
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

    std::map<gtirb::UUID, ElfSymbolInfo> SymbolInfo;
    std::map<gtirb::UUID, ElfSymbolTabIdxInfo> SymbolTabIdxInfo;
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
    if(!SymbolInfo.empty())
    {
        Module->addAuxData<gtirb::schema::ElfSymbolInfoAD>(std::move(SymbolInfo));
    }
    if(!SymbolTabIdxInfo.empty())
    {
        Module->addAuxData<gtirb::schema::ElfSymbolTabIdxInfoAD>(std::move(SymbolTabIdxInfo));
    }
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

    std::set<ElfDynamicEntry> DynamicEntryTuples;
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
