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

    // FIXME: We should either rename this AuxData table or split it.
    auto* SectionProperties = Module.getAuxData<gtirb::schema::ElfSectionProperties>();

    // FIXME: Error handling.
    if(!SectionProperties)
    {
        throw std::logic_error("missing elfSectionProperties AuxData table");
    }

    for(const auto& Section : Module.sections())
    {
        assert(Section.getAddress() && "Section has no address.");
        assert(Section.getSize() && "Section has non-calculable size.");

        auto It = SectionProperties->find(Section.getUUID());

        // FIXME: Error handling.
        if(It == SectionProperties->end())
        {
            throw std::logic_error("Section " + Section.getName()
                                   + " missing from elfSectionProperties AuxData table");
        }

        auto [Type, Flags] = It->second;
        Sections.push_back(
            {Section.getName(), *Section.getSize(), *Section.getAddress(), Type, Flags});
    }

    Program.insert("section_complete", std::move(Sections));
}
