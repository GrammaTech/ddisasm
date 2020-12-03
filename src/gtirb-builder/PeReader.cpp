//===- PeReader.cpp  --------------------------------------------*- C++ -*-===//
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
#include <boost/filesystem.hpp>
#include <boost/uuid/uuid_io.hpp>
namespace fs = boost::filesystem;
#include "LIEF/PE.h"

#include "PeReader.h"

PeReader::PeReader(std::string Path, std::shared_ptr<LIEF::Binary> Binary)
    : GtirbBuilder(Path, Binary)
{
    Pe = std::dynamic_pointer_cast<LIEF::PE::Binary>(Binary);
    assert(Pe && "Expected PE");
};

void PeReader::initModule()
{
    gtirb::Addr ImageBase = gtirb::Addr(Pe->optional_header().imagebase());
    Module->setPreferredAddr(ImageBase);
    GtirbBuilder::initModule();
}

void PeReader::buildSections()
{
    std::map<gtirb::UUID, SectionProperties> SectionProperties;

    for(auto &Section : Pe->sections())
    {
        using Flags = LIEF::PE::SECTION_CHARACTERISTICS;
        bool Executable = Section.has_characteristic(Flags::IMAGE_SCN_MEM_EXECUTE);
        bool Readable = Section.has_characteristic(Flags::IMAGE_SCN_MEM_READ);
        bool Writable = Section.has_characteristic(Flags::IMAGE_SCN_MEM_WRITE);
        bool Initialized = !Section.has_characteristic(Flags::IMAGE_SCN_CNT_UNINITIALIZED_DATA);
        bool Allocated = Readable;

        // Skip sections that are not loaded into memory.
        if(!Allocated)
        {
            continue;
        }

        gtirb::Section *S = Module->addSection(*Context, Section.name());

        // Add section flags to GTIRB Section.
        if(Allocated)
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

        // Add named section to GTIRB Module.
        gtirb::Addr ImageBase = gtirb::Addr(Pe->optional_header().imagebase());
        gtirb::Addr Addr = gtirb::Addr(ImageBase + Section.virtual_address());
        uint64_t Size = Section.virtual_size();
        if(Initialized)
        {
            // Add allocated section contents to a single, contiguous ByteInterval.
            std::vector<uint8_t> Bytes = Section.content();
            S->addByteInterval(*Context, Addr, Bytes.begin(), Bytes.end(), Size, Bytes.size());
        }
        else
        {
            // Add an uninitialized section.
            S->addByteInterval(*Context, Addr, Size, 0);
        }

        SectionProperties[S->getUUID()] = {0, Section.characteristics()};
    }

    Module->addAuxData<gtirb::schema::ElfSectionProperties>(std::move(SectionProperties));
}

void PeReader::buildSymbols()
{
    std::vector<gtirb::UUID> ImportedSymbols;
    std::vector<gtirb::UUID> ExportedSymbols;
    for(auto &Entry : importEntries())
    {
        std::string &Function = std::get<2>(Entry);
        gtirb::Symbol *Symbol = Module->addSymbol(*Context, Function);
        ImportedSymbols.push_back(Symbol->getUUID());
    }
    for(auto &Entry : exportEntries())
    {
        gtirb::Addr Addr(std::get<0>(Entry));
        std::string &Name = std::get<2>(Entry);
        gtirb::Symbol *Symbol = Module->addSymbol(*Context, Addr, Name);
        ExportedSymbols.push_back(Symbol->getUUID());
    }
    Module->addAuxData<gtirb::schema::PeImportedSymbols>(std::move(ImportedSymbols));
    Module->addAuxData<gtirb::schema::PeExportedSymbols>(std::move(ExportedSymbols));
}

void PeReader::addEntryBlock()
{
    gtirb::Addr ImageBase = gtirb::Addr(Pe->optional_header().imagebase());
    gtirb::Addr Entry = gtirb::Addr(ImageBase + Pe->optional_header().addressof_entrypoint());
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

void PeReader::addAuxData()
{
    // Add `binaryType' aux data table.
    std::vector<std::string> BinaryType = {"EXEC"};
    Module->addAuxData<gtirb::schema::BinaryType>(std::move(BinaryType));

    // Add `libraries' aux data table.
    Module->addAuxData<gtirb::schema::Libraries>(Pe->imported_libraries());

    // TODO: Add `libraryPaths' aux data table.
    Module->addAuxData<gtirb::schema::LibraryPaths>({});

    // Add `importEntries' aux data table.
    Module->addAuxData<gtirb::schema::ImportEntries>(importEntries());

    // Add `exportEntries' aux data table.
    Module->addAuxData<gtirb::schema::ExportEntries>(exportEntries());

    // Add `PEResources' aux data table
    Module->addAuxData<gtirb::schema::PEResources>(Resources());
}

std::vector<Resource> PeReader::Resources()
{
#define WR(ss, d, n) ss.write(reinterpret_cast<const char *>(&d), n)

    std::vector<Resource> rsrc_vec;

    if(Pe->has_resources())
    {
        auto &rsrc_dir_node = Pe->resources();

        const uint8_t header[] = {0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00,
                                  0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        auto rsrc_dir = dynamic_cast<LIEF::PE::ResourceDirectory *>(&rsrc_dir_node);
        for(auto &type_node : rsrc_dir_node.childs())
        {
            for(auto &id_node : type_node.childs())
            {
                for(auto &lang_node : id_node.childs())
                {
                    if(lang_node.is_data())
                    {
                        auto dn = dynamic_cast<LIEF::PE::ResourceData *>(&lang_node);
                        std::stringstream ss;

                        // 32b data length
                        uint32_t tmp = dn->content().size();
                        uint16_t tmp16 = 0;
                        WR(ss, tmp, 4);

                        // 32b header length
                        uint32_t header_len = 0x18;
                        int name_len = 4, type_len = 4, padding_len = 0;
                        if(type_node.has_name())
                            type_len = ((type_node.name().size() + 1) * sizeof(uint16_t));
                        if(id_node.has_name())
                            name_len = ((id_node.name().size() + 1) * sizeof(uint16_t));
                        header_len += name_len + type_len;
                        if(header_len % 4 == 2)
                            padding_len = 2;
                        header_len += padding_len;
                        WR(ss, header_len, 4);

                        // 32b type id, or unicode type name
                        if(type_node.has_name())
                        {
                            std::u16string n = type_node.name();
                            ss.write(reinterpret_cast<char *>(n.data()), type_len);
                        }
                        else
                        {
                            tmp16 = 0xffff;
                            WR(ss, tmp16, 2);
                            tmp16 = (uint16_t)type_node.id();
                            WR(ss, tmp16, 2);
                        }

                        // 32b id, or unicode name
                        if(id_node.has_name())
                        {
                            std::u16string n = id_node.name();
                            ss.write(reinterpret_cast<char *>(n.data()), name_len);
                        }
                        else
                        {
                            tmp16 = 0xffff;
                            WR(ss, tmp16, 2);
                            tmp16 = (uint16_t)id_node.id();
                            WR(ss, tmp16, 2);
                        }

                        // padding?
                        if(padding_len == 2)
                        {
                            tmp16 = 0x0000;
                            WR(ss, tmp16, 2);
                        }

                        // uint32_t DataVersion;
                        // TODO : How is this different that the below 'version' field?
                        tmp = rsrc_dir->major_version() << 16 | rsrc_dir->minor_version();
                        WR(ss, tmp, 4);

                        // uint16_t MemoryFlags;
                        // Reserved for backwards compatibility.  Determined empirically from some
                        // examples.
                        tmp16 = 0x1030;
                        WR(ss, tmp16, 2);

                        // uint16_t LanguageId;
                        tmp16 = lang_node.id();
                        WR(ss, tmp16, 2);

                        // uint32_t Version;
                        tmp = rsrc_dir->major_version() << 16 | rsrc_dir->minor_version();
                        WR(ss, tmp, 4);

                        // uint32_t Characteristics;
                        tmp = rsrc_dir->characteristics();
                        WR(ss, tmp, 4);

                        std::vector<uint8_t> d = dn->content();

                        // LIEF ResourceData node 'offset' member is the offset in the file image of
                        // the resource data.  We need to identify it in the byte-intervals via EA.
                        // EA = <data offset> - <section image offset> + <section RVA> + <image
                        // base>
                        auto rsrc_section = Pe->section_from_offset(dn->offset());
                        uint64_t data_ea = dn->offset() - rsrc_section.offset()
                                           + rsrc_section.virtual_address()
                                           + Pe->optional_header().imagebase();
                        auto bis = Module->findByteIntervalsOn(gtirb::Addr(data_ea));
                        if(bis)
                        {
                            uint64_t bi_offset =
                                data_ea - static_cast<uint64_t>(bis.front().getAddress().value());
                            gtirb::Offset gtoff = gtirb::Offset(bis.front().getUUID(), bi_offset);
                            std::vector<uint8_t> header_vec;
                            for(char c : ss.str())
                                header_vec.push_back(c);

                            const uint8_t *bi_data = reinterpret_cast<const uint8_t *>(
                                                         bis.front().rawBytes<const uint8_t *>())
                                                     + bi_offset;

                            // sanity check
                            if(memcmp(dn->content().data(), bi_data, dn->content().size()) != 0)
                            {
                                std::cout << "[WARNING] PE Resource data in IR does not match data "
                                             "in original.\n";
                            }

                            // Add the resource to the vector to be added as the aux data
                            rsrc_vec.push_back({header_vec, gtoff, d.size()});
                        }
                        else
                            std::cout << "[WARNING] No byte interval found for resource, resource "
                                         "data will be incomplete.\n";
                    }
                }
            }
        }
    }
    else
        std::cout << "[INFO] PE: No resources...\n";

    return rsrc_vec;
}

std::vector<ImportEntry> PeReader::importEntries()
{
    std::vector<ImportEntry> ImportEntries;
    for(auto &Import : Pe->imports())
    {
        uint64_t ImageBase = Pe->optional_header().imagebase();
        for(auto &Entry : Import.entries())
        {
            std::string ImportName = fs::change_extension(Import.name(), "").string();
            int64_t Ordinal = Entry.is_ordinal() ? Entry.ordinal() : -1;
            std::string Function = Entry.is_ordinal()
                                       ? ImportName + '@' + std::to_string(Entry.ordinal())
                                       : Entry.name();
            ImportEntries.push_back(
                {ImageBase + Entry.iat_address(), Ordinal, Function, Import.name()});
        }
    }
    return ImportEntries;
}

std::vector<ExportEntry> PeReader::exportEntries()
{
    std::vector<ExportEntry> ExportEntries;
    if(Pe->has_exports())
    {
        uint64_t ImageBase = Pe->optional_header().imagebase();
        for(auto &Entry : Pe->get_export().entries())
        {
            ExportEntries.push_back({ImageBase + Entry.address(), Entry.ordinal(), Entry.name()});
        }
    }
    return ExportEntries;
}
