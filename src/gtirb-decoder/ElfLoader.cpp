//===- ElfLoader.cpp --------------------------------------------*- C++ -*-===//
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

#include "ElfLoader.h"

#include "../AuxDataSchema.h"

void ElfSymbolDecoder::load(const gtirb::Module &Module)
{
    // Find extra ELF symbol information in aux data.
    auto *SymbolInfo = Module.getAuxData<gtirb::schema::ElfSymbolInfoAD>();

    // Load symbols with extra symbol information, if available.
    for(auto &Symbol : Module.symbols())
    {
        std::string Name = Symbol.getName();
        gtirb::Addr Addr = Symbol.getAddress().value_or(gtirb::Addr(0));

        ElfSymbolInfo Info = {0, "NOTYPE", "GLOBAL", "DEFAULT", 0};

        if(SymbolInfo)
        {
            auto Found = SymbolInfo->find(Symbol.getUUID());

            // FIXME: Error handling
            if(Found == SymbolInfo->end())
            {
                throw std::logic_error("Symbol " + Symbol.getName()
                                       + " missing from elfSymbolInfo AuxData table");
            }

            Info = Found->second;
        }

        auto [Size, Type, Binding, Visibility, SectionIndex] = Info;
        Symbols.push_back({Addr, Size, Type, Binding, Visibility, SectionIndex, Name});
    }
}

void ElfSymbolDecoder::populate(DatalogProgram &Program)
{
    // Program.insert("symbol", Symbols);
}
