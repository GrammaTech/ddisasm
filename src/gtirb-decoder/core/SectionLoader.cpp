//===- SectionLoader.cpp ----------------------------------------*- C++ -*-===//
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
#include "SectionLoader.h"

#include "../../AuxDataSchema.h"

void SectionLoader(const gtirb::Module& Module, DatalogProgram& Program)
{
    std::vector<relations::Section> Sections;
    std::vector<relations::SectionProperty> SectionProperty;
    std::vector<relations::SectionProperties> SectionProperties;

    auto* SectProperties = Module.getAuxData<gtirb::schema::SectionProperties>();

    if(Module.getFileFormat() == gtirb::FileFormat::ELF && !SectProperties)
    {
        std::cerr << "WARNING: Missing `sectionProperties' AuxData table\n";
    }

    auto* Alignment = Module.getAuxData<gtirb::schema::Alignment>();

    if(!Alignment)
    {
        std::cerr << "WARNING: Missing `alignment' AuxData table\n";
    }

    std::map<gtirb::UUID, uint64_t> SectionIndexes;
    if(auto* T = Module.getAuxData<gtirb::schema::SectionIndex>())
    {
        for(auto [Index, Uuid] : *T)
        {
            SectionIndexes[Uuid] = Index;
        }
    }

    uint8_t Flag = 0;
    for(const auto& Section : Module.sections())
    {
        bool R = Section.isFlagSet(gtirb::SectionFlag::Readable);
        bool W = Section.isFlagSet(gtirb::SectionFlag::Writable);
        bool E = Section.isFlagSet(gtirb::SectionFlag::Executable);
        bool L = Section.isFlagSet(gtirb::SectionFlag::Loaded);
        bool I = Section.isFlagSet(gtirb::SectionFlag::Initialized);
        bool T = Section.isFlagSet(gtirb::SectionFlag::ThreadLocal);
        if(!R && !W && !E && !L && !I && !T)
        {
            // If no section flag is available, set them by default
            R = true;
            W = false;
            E = true;
            L = true;
            I = false;
            T = false;
        }

        if(!Section.isFlagSet(gtirb::SectionFlag::Loaded))
        {
            continue;
        }
        assert(Section.getAddress() && "Section has no address.");
        assert(Section.getSize() && "Section has non-calculable size.");

        if(R)
            SectionProperty.push_back({Section.getName(), "Readable"});
        if(W)
            SectionProperty.push_back({Section.getName(), "Writable"});
        if(E)
            SectionProperty.push_back({Section.getName(), "Executable"});
        if(L)
            SectionProperty.push_back({Section.getName(), "Loaded"});
        if(I)
            SectionProperty.push_back({Section.getName(), "Initialized"});
        if(T)
            SectionProperty.push_back({Section.getName(), "ThreadLocal"});

        uint64_t Type = 0;
        uint64_t Flags = 0;
        if(SectProperties)
        {
            if(auto It = SectProperties->find(Section.getUUID()); It != SectProperties->end())
            {
                Type = std::get<0>(It->second);
                Flags = std::get<1>(It->second);
            }
            else
            {
                std::cerr << "WARNING: Section missing from `elfSectionProperties' AuxData table: "
                          << Section.getName() << '\n';
            }
        }
        SectionProperties.push_back({Section.getName(), Type, Flags});

        uint64_t Align = 0;
        if(Alignment)
        {
            if(auto It = Alignment->find(Section.getUUID()); It != Alignment->end())
            {
                Align = It->second;
            }
        }

        uint64_t Index = SectionIndexes[Section.getUUID()];

        Sections.push_back(
            {Section.getName(), *Section.getSize(), *Section.getAddress(), Align, Index});
    }

    Program.insert("section", std::move(Sections));
    Program.insert("section_property", std::move(SectionProperty));
    Program.insert("section_properties", std::move(SectionProperties));
}
