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
    std::cout << "WML: addAuxData called\n";

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

    Resources();
}

class Resource
{
    std::vector<uint8_t> getRESHeader(void);
    std::vector<uint8_t> getRawData(void);

    uint32_t TypeNameOrId;
    uint32_t NameOrId;
    std::u16string TypeString; // only used if TypeNameOrId == 0xffff
    std::u16string NameString; // only used if NameOrId == 0xffff
    uint32_t DataVersion;
    uint16_t MemoryFlags;
    uint16_t LanguageId;
    uint32_t Version;
    uint32_t Characteristics;

    long Offset; // offset into what?

private:
    // gtirb_bi_and_offset getByteIntervalRef(void);
    /*	typedef struct
    {
        uint32_t DataSize;
        uint32_t HeaderSize;
            // if first word is 0xffff, next word is id, otherwise,
            // first word is first unicode char of string name, null terminated
        uint32_t TYPE;
            // if first word is 0xffff, next word is id, otherwise,
            // first word is first unicode char of string name, null terminated
        uint32_t NAME;
        uint32_t DataVersion;
        uint16_t MemoryFlags;
        uint16_t LanguageId;
        uint32_t Version;
        uint32_t Characteristics;
        // MAY need WORD padding here if name or type was a string,
        // to have the following data DWORD aligned
    } RESOURCEHEADER;
    */
};

// std::vector<Resource> PeReader::Resources()
void PeReader::Resources()
{
#define WR4(ss, d) ss.write(reinterpret_cast<char *>(&d), 4)
#define WR2(ss, d) ss.write(reinterpret_cast<char *>(&d), 2)

    std::cout << "WML: Checking for resources...\n";
    if(Pe->has_resources())
    {
        std::cout << "WML: resources found!\n";
        auto &rsrc_dir_node = Pe->resources();
        // Pe->data_directory(LIEF::PE::DATA_DIRECTORY::RESOURCE_TABLE));
        // auto characteristics = rsrc_dir.characteristics();
        // auto version = rsrc_dir.major_version() << rsrc_dir.minor_version();

        std::ofstream output_res;
        output_res.open("foo.res",
                        std::ofstream::out | std::ofstream::binary | std::ofstream::trunc);
        const char header[] = {0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00,
                               0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        output_res.write(header, 32);
        auto rsrc_dir = dynamic_cast<LIEF::PE::ResourceDirectory *>(&rsrc_dir_node);
        for(auto &type_node : rsrc_dir_node.childs())
        {
            auto type = type_node.id();
            std::cout << "\ttype node " << type << " ...\n";
            for(auto &id_node : type_node.childs())
            {
                std::cout << "\t\tid node " << id_node.id() << " ...\n";

                for(auto &lang_node : id_node.childs())
                {
                    std::cout << "\t\t\tlang node " << lang_node.id() << " ...\n";
                    std::cout << lang_node << "\n";

                    auto language_id = lang_node.id();
                    if(lang_node.is_data())
                    {
                        auto dn = dynamic_cast<LIEF::PE::ResourceData *>(&lang_node);
                        std::stringstream ss;

                        // 32b data length
                        uint32_t tmp = dn->content().size();
                        uint16_t tmp16 = 0;
                        WR4(ss, tmp);

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
                        WR4(ss, header_len);

                        // 32b type id, or unicode type name
                        if(type_node.has_name())
                        {
                            std::u16string n = type_node.name();
                            ss.write(reinterpret_cast<char *>(n.data()), type_len);
                            std::cout << "\t\t\\tType len: used " << type_len << ":"
                                      << type_node.name().length();
                        }
                        else
                        {
                            tmp16 = 0xffff;
                            WR2(ss, tmp16);
                            tmp16 = (uint16_t)type_node.id();
                            WR2(ss, tmp16);
                        }

                        // 32b id, or unicode name
                        if(id_node.has_name())
                        {
                            std::u16string n = id_node.name();
                            ss.write(reinterpret_cast<char *>(n.data()), name_len);
                            std::cout << "\t\t\\tName len: used " << name_len << ":"
                                      << id_node.name().length();
                        }
                        else
                        {
                            tmp16 = 0xffff;
                            WR2(ss, tmp16);
                            tmp16 = (uint16_t)id_node.id();
                            WR2(ss, tmp16);
                        }

                        // padding?
                        std::cout << "\t\t\t\tLen: header_len (" << header_len << ") \n";
                        if(padding_len == 2)
                        {
                            std::cout << "\t\t\t\tLen: adding padding \n";
                            tmp16 = 0x0000;
                            WR2(ss, tmp16);
                        }

                        // uint32_t DataVersion;
                        // TODO : How is this different that the below 'version' field?
                        tmp = rsrc_dir->major_version() << 16 | rsrc_dir->minor_version();
                        // tmp = 0x66778899;
                        WR4(ss, tmp);

                        // uint16_t MemoryFlags;
                        // Reserved for backwards compatibility
                        tmp16 = 0x1030;
                        WR2(ss, tmp16);

                        // uint16_t LanguageId;
                        tmp16 = lang_node.id();
                        WR2(ss, tmp16);

                        // uint32_t Version;
                        tmp = rsrc_dir->major_version() << 16 | rsrc_dir->minor_version();
                        WR4(ss, tmp);

                        // uint32_t Characteristics;
                        tmp = rsrc_dir->characteristics();
                        WR4(ss, tmp);

                        // header_len += 4;
                        // tmp = 0x44444444;
                        // WR4(ss, tmp);

                        std::cout << "\t\t\t\tResource: " << dn->id() << " offset " << dn->offset()
                                  << "\n\t";
                        for(char c : ss.str())
                            std::cout << std::hex << std::setfill('0') << std::setw(2)
                                      << (unsigned int)c << " ";

                        output_res.write(ss.str().data(), header_len);

                        std::vector<uint8_t> d = dn->content();
                        output_res.write(reinterpret_cast<const char *>(d.data()), d.size());

						// final padding on content to ensure the following header is DWORD aligned
                        if(d.size() % 4 != 0)
                        {
                            std::cout << "\t\t\t\tLen: adding padding \n";
                            tmp = 0x0000;
                            output_res.write(reinterpret_cast<char *>(&tmp), 4 - d.size() % 4);
                        }

                        // tmp = 0x55555555;
                        // WR4(output_res, tmp);

                        // how to find the byte interval and offset for the content
                        // auto offset = dn->offset();
                    }
                }
            }
        }

        output_res.close();
    }
    else
        std::cout << "WML: No resources...\n";
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
