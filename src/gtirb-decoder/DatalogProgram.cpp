//===- DatalogProgram.h -----------------------------------------*- C++ -*-===//
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
#include <fstream>

#include <gtirb/gtirb.hpp>

#include "DatalogLoader.h"
#include "DatalogProgram.h"

#include "ElfLoader.h"

std::optional<DatalogProgram> DatalogProgram::load(gtirb::Module &Module)
{
    // TODO: Target registration
    switch(Module.getISA())
    {
        case gtirb::ISA::X64:
        {
            ElfX64Loader Loader;
            Loader.decode(Module);
            return Loader.program();
        }
        case gtirb::ISA::ARM64:
        {
            ElfArm64Loader Loader;
            Loader.decode(Module);
            return Loader.program();
        }
    }
    return std::nullopt;
}

void DatalogProgram::writeFacts(const std::string &Directory)
{
    std::ios_base::openmode FileMask = std::ios::out;
    for(souffle::Relation *Relation : Program->getInputRelations())
    {
        std::ofstream File(Directory + Relation->getName() + ".facts", FileMask);
        souffle::SymbolTable SymbolTable = Relation->getSymbolTable();
        for(souffle::tuple Tuple : *Relation)
        {
            for(size_t I = 0; I < Tuple.size(); I++)
            {
                if(I > 0)
                {
                    File << "\t";
                }
                if(Relation->getAttrType(I)[0] == 's')
                {
                    File << SymbolTable.resolve(Tuple[I]);
                }
                else
                {
                    File << Tuple[I];
                }
            }
            File << std::endl;
        }
        File.close();
    }
}
