//===- RawLoader.cpp --------------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2021 GrammaTech, Inc.
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
//  GNU Affero General Public
//  License for more details.
//
//  This project is sponsored by the Office of Naval Research, One Liberty
//  Center, 875 N. Randolph Street, Arlington, VA 22203 under contract #
//  N68335-17-C-0700.  The content of the information does not necessarily
//  reflect the position or policy of the Government and no official
//  endorsement should be inferred.
//
//===----------------------------------------------------------------------===//

#include "RawLoader.h"

#include "../../AuxDataSchema.h"
#include "../Relations.h"

void RawEntryLoader(const gtirb::Module &Module, souffle::SouffleProgram &Program)
{
    std::vector<gtirb::Addr> Entries;
    if(auto *RawEntries = Module.getAuxData<gtirb::schema::RawEntries>())
    {
        for(const auto &EA : *RawEntries)
        {
            Entries.push_back(gtirb::Addr(EA));
        }
    }
    relations::insert(Program, "entry_point", std::move(Entries));
    std::vector<gtirb::Addr> Targets;
    for(auto &CodeBlock : Module.code_blocks())
    {
        std::optional<gtirb::Addr> Addr = CodeBlock.getAddress();
        if(Addr)
        {
            Targets.push_back(*Addr);
        }
    }
    relations::insert(Program, "known_code", std::move(Targets));
}
