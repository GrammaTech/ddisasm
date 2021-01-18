//===- PeReader.cpp --------------------------------------------*- C++ -*-===//
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

#include "PeReader.h"
#include "PE/Structures.hpp"

PeReader::PeReader(std::string Path, std::shared_ptr<LIEF::Binary> Binary)
    : GtirbBuilder(Path, Binary)
{
    Pe = std::dynamic_pointer_cast<LIEF::PE::Binary>(Binary);
    assert(Pe && "Expected PE");
};

void PeReader::buildSections()
{
    std::map<uint64_t, gtirb::UUID> SectionIndex;
    std::map<gtirb::UUID, SectionProperties> SectionProperties;
    std::map<gtirb::UUID, uint64_t> Alignment;

    uint64_t Index = 0;
    for(auto &Section : Pe->sections())
    {
        bool Loaded = Section.virtual_size() > 0;
        bool Executable = Section.has_characteristic(LIEF::PE::SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_EXECUTE);
        bool Writable = Section.has_characteristic(LIEF::PE::SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_WRITE);
        bool Initialized = Loaded && Section.has_characteristic(LIEF::PE::SECTION_CHARACTERISTICS::IMAGE_SCN_CNT_INITIALIZED_DATA);

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

        uint64_t imagebase = Pe->optional_header().imagebase();
        gtirb::Addr Addr = gtirb::Addr(imagebase + Section.virtual_address());

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
            S->addByteInterval(*Context, Addr, Section.virtual_size(), 0);
        }

        // Add section index and raw section properties to aux data.
        auto &Uuid = S->getUUID();
        Alignment[Uuid] = Pe->optional_header().section_alignment();
        SectionIndex[Index] = Uuid;
        SectionProperties[Uuid] = {static_cast<uint64_t>(*Section.types().begin()), // TODO: pretty useless
                                   static_cast<uint64_t>(Section.characteristics())};

        Index++;
    }

    Module->addAuxData<gtirb::schema::Alignment>(std::move(Alignment));
    Module->addAuxData<gtirb::schema::ElfSectionIndex>(std::move(SectionIndex));
    Module->addAuxData<gtirb::schema::ElfSectionProperties>(std::move(SectionProperties));
}

void PeReader::buildSymbols()
{
}

void PeReader::addEntryBlock()
{
    gtirb::Addr Entry = gtirb::Addr(Pe->entrypoint()); // absolute
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
    std::vector<std::string> BinaryType;
    if(Pe->header().has_characteristic(LIEF::PE::HEADER_CHARACTERISTICS::IMAGE_FILE_DLL))
        BinaryType.emplace_back("DYN");
    else
        BinaryType.emplace_back("EXEC");
    Module->addAuxData<gtirb::schema::BinaryType>(std::move(BinaryType));

    std::vector<std::string> Libraries = Pe->imported_libraries();
    Module->addAuxData<gtirb::schema::Libraries>(std::move(Libraries));
}
