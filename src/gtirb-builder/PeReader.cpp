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

    // Add `PeResources' aux data table
    Module->addAuxData<gtirb::schema::PeResources>(resources());
}

std::vector<PeResource> PeReader::resources()
{
//#define WR(ss, d, n) ss.write(reinterpret_cast<const char *>(&d), n)
    auto WR = [](std::stringstream &ss, auto d, int n) {
        ss.write(reinterpret_cast<const char *>(&d), n);
    };

    std::vector<PeResource> CollectedResources;

    if(Pe->has_resources())
    {
        auto &ResourceDirNode = Pe->resources();

        const uint8_t Header[] = {0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00,
                                  0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        auto ResourceDir = dynamic_cast<LIEF::PE::ResourceDirectory *>(&ResourceDirNode);
        for(auto &TypeNode : ResourceDirNode.childs())
        {
            for(auto &IdNode : TypeNode.childs())
            {
                for(auto &LanguageNode : IdNode.childs())
                {
                    if(LanguageNode.is_data())
                    {
                        auto DataNode = dynamic_cast<LIEF::PE::ResourceData *>(&LanguageNode);
                        std::stringstream ss;

                        // 32b data length
                        uint32_t Tmp = DataNode->content().size();
                        uint16_t Tmp16 = 0;
                        WR(ss, Tmp, 4);

                        // 32b Header length
                        uint32_t HeaderLen = 0x18;
                        int NameLen = 4, TypeLen = 4, PaddingLen = 0;
                        if(TypeNode.has_name())
                            TypeLen = ((TypeNode.name().size() + 1) * sizeof(uint16_t));
                        if(IdNode.has_name())
                            NameLen = ((IdNode.name().size() + 1) * sizeof(uint16_t));
                        HeaderLen += NameLen + TypeLen;
                        if(HeaderLen % 4 == 2)
                            PaddingLen = 2;
                        HeaderLen += PaddingLen;
                        WR(ss, HeaderLen, 4);

                        // 32b type id, or unicode type name
                        if(TypeNode.has_name())
                        {
                            std::u16string n = TypeNode.name();
                            ss.write(reinterpret_cast<char *>(n.data()), TypeLen);
                        }
                        else
                        {
                            Tmp16 = 0xffff;
                            WR(ss, Tmp16, 2);
                            Tmp16 = (uint16_t)TypeNode.id();
                            WR(ss, Tmp16, 2);
                        }

                        // 32b id, or unicode name
                        if(IdNode.has_name())
                        {
                            std::u16string n = IdNode.name();
                            ss.write(reinterpret_cast<char *>(n.data()), NameLen);
                        }
                        else
                        {
                            Tmp16 = 0xffff;
                            WR(ss, Tmp16, 2);
                            Tmp16 = (uint16_t)IdNode.id();
                            WR(ss, Tmp16, 2);
                        }

                        // padding?
                        if(PaddingLen == 2)
                        {
                            Tmp16 = 0x0000;
                            WR(ss, Tmp16, 2);
                        }

                        // uint32_t DataVersion;
                        // TODO : How is this different that the below 'version' field?
                        Tmp = ResourceDir->major_version() << 16 | ResourceDir->minor_version();
                        WR(ss, Tmp, 4);

                        // uint16_t MemoryFlags;
                        // Reserved for backwards compatibility.  Determined empirically from some
                        // examples.
                        Tmp16 = 0x1030;
                        WR(ss, Tmp16, 2);

                        // uint16_t LanguageId;
                        Tmp16 = LanguageNode.id();
                        WR(ss, Tmp16, 2);

                        // uint32_t Version;
                        Tmp = ResourceDir->major_version() << 16 | ResourceDir->minor_version();
                        WR(ss, Tmp, 4);

                        // uint32_t Characteristics;
                        Tmp = ResourceDir->characteristics();
                        WR(ss, Tmp, 4);

                        std::vector<uint8_t> DataFromLIEF = DataNode->content();

                        // LIEF ResourceData node 'offset' member is the offset in the file image of
                        // the resource data.  We need to identify it in the byte-intervals via EA.
                        // EA = <data offset> - <section image offset> + <section RVA> + <image
                        // base>
                        auto ResourceSection = Pe->section_from_offset(DataNode->offset());
                        uint64_t DataEA = DataNode->offset() - ResourceSection.offset()
                                           + ResourceSection.virtual_address()
                                           + Pe->optional_header().imagebase();
                        auto DataBIs = Module->findByteIntervalsOn(gtirb::Addr(DataEA));
                        if(DataBIs)
                        {
                            uint64_t BiOffset =
                                DataEA - static_cast<uint64_t>(DataBIs.front().getAddress().value());
                            gtirb::Offset GtirbOffset = gtirb::Offset(DataBIs.front().getUUID(), BiOffset);
                            std::vector<uint8_t> HeaderVec;
                            for(char c : ss.str())
                                HeaderVec.push_back(c);

                            const uint8_t *DataInBI =
                                reinterpret_cast<const uint8_t *>(
                                    DataBIs.front().rawBytes<const uint8_t *>())
                                + BiOffset;

                            // sanity check
                            if(memcmp(DataNode->content().data(), DataInBI, DataNode->content().size()) != 0)
                            {
                                std::cerr << "WARNING: PE Resource data in IR does not match data "
                                             "in original.\n";
                            }

                            // Add the resource to the vector to be added as the aux data
                            CollectedResources.push_back({HeaderVec, GtirbOffset, DataFromLIEF.size()});
                        }
                        else
                            std::cerr << "WARNING: No byte interval found for resource, resource "
                                         "data will be incomplete.\n";
                    }
                }
            }
        }
    }
    else
        std::cout << "[INFO] PE: No resources...\n";

    return CollectedResources;
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
