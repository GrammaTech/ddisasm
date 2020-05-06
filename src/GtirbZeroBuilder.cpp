//===- GtirbZeroBuilder.cpp -------------------------------------*- C++ -*-===//
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

#include "GtirbZeroBuilder.h"
#include "AuxDataSchema.h"
#include "BinaryReader.h"
#include "LIEFBinaryReader.h"

bool isExeSection(const SectionProperties &s)
{
    uint64_t flags = std::get<1>(s);
    return flags & static_cast<int>(LIEF::ELF::ELF_SECTION_FLAGS::SHF_EXECINSTR);
};

bool isNonZeroDataSection(const SectionProperties &s)
{
    uint64_t type = std::get<0>(s);
    uint64_t flags = std::get<1>(s);

    bool is_allocated = flags & static_cast<int>(LIEF::ELF::ELF_SECTION_FLAGS::SHF_ALLOC);
    bool is_not_executable =
        !(flags & static_cast<int>(LIEF::ELF::ELF_SECTION_FLAGS::SHF_EXECINSTR));
    // SHT_NOBITS is not considered here because it is for data sections but without initial
    // data (zero initialized)
    bool is_non_zero_program_data =
        type == static_cast<int>(LIEF::ELF::ELF_SECTION_TYPES::SHT_PROGBITS)
        || type == static_cast<int>(LIEF::ELF::ELF_SECTION_TYPES::SHT_INIT_ARRAY)
        || type == static_cast<int>(LIEF::ELF::ELF_SECTION_TYPES::SHT_FINI_ARRAY)
        || type == static_cast<int>(LIEF::ELF::ELF_SECTION_TYPES::SHT_PREINIT_ARRAY);
    return is_allocated && is_not_executable && is_non_zero_program_data;
};

bool isAllocatedSection(int flags)
{
    return (flags & static_cast<int>(LIEF::ELF::ELF_SECTION_FLAGS::SHF_ALLOC));
}

std::string gtirb::auxdata_traits<SymbolPrefixInfo>::type_name()
{
    return gtirb::auxdata_traits<
        std::tuple<uint64_t, std::string>>::type_name();
}

std::string gtirb::auxdata_traits<ElfSymbolInfo>::type_name()
{
    return gtirb::auxdata_traits<
        std::tuple<uint64_t, std::string, std::string, std::string, uint64_t>>::type_name();
}

void gtirb::auxdata_traits<SymbolPrefixInfo>::toBytes(const SymbolPrefixInfo& Object, to_iterator It)
{
    auxdata_traits<std::tuple<uint64_t, std::string>>::toBytes(
        std::make_tuple(Object.index, Object.prefix),
        It);
}

void gtirb::auxdata_traits<ElfSymbolInfo>::toBytes(const ElfSymbolInfo &Object, to_iterator It)
{
    auxdata_traits<std::tuple<uint64_t, std::string, std::string, std::string, uint64_t>>::toBytes(
        std::make_tuple(Object.Size, Object.Type, Object.Scope, Object.Visibility,
                        Object.SectionIndex),
        It);
}

gtirb::from_iterator gtirb::auxdata_traits<SymbolPrefixInfo>::fromBytes(SymbolPrefixInfo& Object,
                                                                     from_iterator It)
{
    std::tuple<uint64_t, std::string> Tuple;
    It = auxdata_traits<
        std::tuple<uint64_t, std::string>>::fromBytes(Tuple,
                                                                                          It);
    Object.index = std::get<0>(Tuple);
    Object.prefix = std::get<1>(Tuple);

    return It;
}

gtirb::from_iterator gtirb::auxdata_traits<ElfSymbolInfo>::fromBytes(ElfSymbolInfo &Object,
                                                                     from_iterator It)
{
    std::tuple<uint64_t, std::string, std::string, std::string, uint64_t> Tuple;
    It = auxdata_traits<
        std::tuple<uint64_t, std::string, std::string, std::string, uint64_t>>::fromBytes(Tuple,
                                                                                          It);
    Object.Size = std::get<0>(Tuple);
    Object.Type = std::get<1>(Tuple);
    Object.Scope = std::get<2>(Tuple);
    Object.Visibility = std::get<3>(Tuple);
    Object.SectionIndex = std::get<4>(Tuple);

    return It;
}

void buildSections(gtirb::Module &module, std::shared_ptr<BinaryReader> binary,
                   gtirb::Context &context)
{
    std::map<gtirb::UUID, SectionProperties> dwarfSections;
    std::map<gtirb::UUID, SectionProperties> allSections;
    std::map<gtirb::UUID, SectionProperties> sectionProperties;
    for(auto &binSection : binary->get_sections())
    {
        gtirb::Section *section = module.addSection(context, binSection.name);
        if(isAllocatedSection(binSection.flags))
        {
            // Create Section object and set common flags

            for(auto flag : binary->get_section_flags(binSection))
            {
                section->addFlag(flag);
            }
            if(auto sectionData =
                   binary->get_section_content_and_address(binSection.name, binSection.address))
            {
                // Add allocated section contents to a single contiguous ByteInterval.
                gtirb::Addr Addr = gtirb::Addr(binSection.address);
                std::vector<uint8_t> &Bytes = std::get<0>(*sectionData);
                if(Bytes.size() < binSection.size)
                {
                    // Fill incomplete section with zeroes.
                    std::cerr << "Warning: Zero filling uninitialized section fragment: "
                              << Addr + Bytes.size() << '-' << Addr + binSection.size << " ("
                              << binSection.name << ")\n";
                    Bytes.resize(binSection.size, 0);
                }
                section->addByteInterval(context, Addr, Bytes.begin(), Bytes.end(),
                                         binSection.size);
            }
            else
            {
                // Add an uninitialized section.
                section->addByteInterval(context, gtirb::Addr(binSection.address), binSection.size,
                                         0);
            }
            // Add object specific flags to elfSectionProperties AuxData table.
            sectionProperties[section->getUUID()] =
                std::make_tuple(binSection.type, binSection.flags);
        } else {
            //TODO: Clean up this component
            static std::vector<std::string> sectionNames{
                ".debug_abbrev",
                ".debug_aranges",
                ".debug_frame",
                ".debug_info",
                ".debug_line",
                ".debug_loc",
                ".debug_macinfo",
                ".debug_types",
                ".debug_str",
                ".debug_ranges",
                ".debug_pubnames",
                ".debug_pubtypes"
            };

            auto gtirbName = binSection.name;
            for(std::string sName : sectionNames)
            {
                if(gtirbName == sName)
                {
                    //Detected the debug section
                    //Debug section isn't allocatable
                    //gtirb::Section *section = gtirb::Section::Create(
                    //    context, binSection.name, gtirb::Addr(binSection.address),
                    //        binSection.size);
                    // TODO: Turn into a separate method
                    gtirb::Section *section = module.addSection(context, binSection.name);
                    for(auto flag : binary->get_section_flags(binSection))
                    {
                        section->addFlag(flag);
                    }
                    if(auto sectionData =
                        binary->get_section_content_and_address(binSection.name,
                        binSection.address))
                    {
                        // Add allocated section contents to a single contiguous ByteInterval.
                        gtirb::Addr Addr = gtirb::Addr(binSection.address);
                        std::vector<uint8_t> &Bytes = std::get<0>(*sectionData);
                        if(Bytes.size() < binSection.size)
                        {
                            // Fill incomplete section with zeroes.
                            std::cerr << "Warning: Zero filling uninitialized section fragment: "
                                      << Addr + Bytes.size() << '-' << Addr + binSection.size << " ("
                                      << binSection.name << ")\n";
                            Bytes.resize(binSection.size, 0);
                        }
                        section->addByteInterval(context, Addr, Bytes.begin(), Bytes.end(),
                                                 binSection.size);
                    }

                    module.addSection(section);
                    dwarfSections[section->getUUID()] =
                        std::make_tuple(binSection.type, binSection.flags);;

                    break;
                }
            }
        }
    }
    module.addAuxData<gtirb::schema::ElfSectionProperties>(std::move(sectionProperties));
    module.addAuxData<gtirb::schema::AllElfSectionProperties>(std::move(allSections));
    module.addAuxData<gtirb::schema::DWARFElfSectionProperties>(std::move(dwarfSections));
}

void buildSymbols(gtirb::Module &module, std::shared_ptr<BinaryReader> binary,
                  gtirb::Context &context)
{
    if(binary->get_binary_format() == gtirb::FileFormat::ELF)
    {
        std::map<gtirb::UUID, ElfSymbolInfo> elfSymbolInfo;
        for(auto &binSymbol : binary->get_symbols())
        {
            // Symbols with special section index do not have an address
            gtirb::Symbol *symbol;
            if(binSymbol.sectionIndex
                   == static_cast<int>(LIEF::ELF::SYMBOL_SECTION_INDEX::SHN_UNDEF)
               || (binSymbol.sectionIndex
                       >= static_cast<int>(LIEF::ELF::SYMBOL_SECTION_INDEX::SHN_LORESERVE)
                   && binSymbol.sectionIndex
                          <= static_cast<int>(LIEF::ELF::SYMBOL_SECTION_INDEX::SHN_HIRESERVE)))
            {
                symbol = module.addSymbol(context, binSymbol.name);
            }
            else
            {
                symbol = module.addSymbol(context, gtirb::Addr(binSymbol.address), binSymbol.name);
            }
            elfSymbolInfo[symbol->getUUID()] = {binSymbol.size, binSymbol.type, binSymbol.scope,
                                                binSymbol.visibility, binSymbol.sectionIndex};
        }
        module.addAuxData<gtirb::schema::ElfSymbolInfoAD>(std::move(elfSymbolInfo));
    }
}

void addEntryBlock(gtirb::Module &Module, std::shared_ptr<BinaryReader> Binary,
                   gtirb::Context &Context)
{
    gtirb::Addr Entry = gtirb::Addr(Binary->get_entry_point());
    if(auto It = Module.findByteIntervalsOn(Entry); !It.empty())
    {
        if(gtirb::ByteInterval &Interval = *It.begin(); Interval.getAddress())
        {
            uint64_t Offset = Entry - *Interval.getAddress();
            gtirb::CodeBlock *Block = Interval.addBlock<gtirb::CodeBlock>(Context, Offset, 0);
            Module.setEntryPoint(Block);
        }
    }
    assert(Module.getEntryPoint() && "Failed to set module entry point.");
}

void addAuxiliaryTables(gtirb::Module &module, std::shared_ptr<BinaryReader> binary)
{
    std::vector<std::string> binaryType = {binary->get_binary_type()};
    module.addAuxData<gtirb::schema::BinaryType>(std::move(binaryType));
    module.addAuxData<gtirb::schema::Relocations>(binary->get_relocations());
    module.addAuxData<gtirb::schema::Libraries>(binary->get_libraries());
    module.addAuxData<gtirb::schema::LibraryPaths>(binary->get_library_paths());
}

std::tuple<gtirb::IR*, LIEF::ARCHITECTURES, LIEF::ENDIANNESS> buildZeroIR(const std::string &filename, gtirb::Context &context)
{
    // Parse binary file
    std::shared_ptr<BinaryReader> binary(new LIEFBinaryReader(filename));
    LIEF::ARCHITECTURES arch;
    LIEF::ENDIANNESS endianness;
    std::tie(arch, endianness) = binary->get_container_info();

    if(!binary->is_valid())
        return std::make_tuple(nullptr, LIEF::ARCHITECTURES::ARCH_NONE, LIEF::ENDIANNESS::ENDIAN_NONE);

    // Intialize IR and Module
    auto ir = gtirb::IR::Create(context);
    gtirb::Module &module = *gtirb::Module::Create(context);
    module.setBinaryPath(filename);
    module.setFileFormat(binary->get_binary_format());

    if (arch == LIEF::ARCHITECTURES::ARCH_X86) {
        module.setISA(gtirb::ISA::X64);
    } else if (arch == LIEF::ARCHITECTURES::ARCH_ARM64) {
        module.setISA(gtirb::ISA::ARM);
    } else {
        assert(false && "unsupported architecture");
    }

    ir->addModule(&module);

    // Populate Module with pre-analysis data
    buildSections(module, binary, context);
    buildSymbols(module, binary, context);
    addEntryBlock(module, binary, context);
    addAuxiliaryTables(module, binary);

    return std::make_tuple(ir, arch, endianness);
}
