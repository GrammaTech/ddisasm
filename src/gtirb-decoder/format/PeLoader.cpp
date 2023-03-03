//===- PeLoader.cpp ---------------------------------------------*- C++ -*-===//
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
#include "PeLoader.h"

void PeSymbolLoader(const gtirb::Module &Module, souffle::SouffleProgram &Program)
{
    if(auto *ExportEntries = Module.getAuxData<gtirb::schema::ExportEntries>())
    {
        relations::insert(Program, "pe_export_entry", *ExportEntries);
    }

    if(auto *ImportEntries = Module.getAuxData<gtirb::schema::ImportEntries>())
    {
        relations::insert(Program, "pe_import_entry", *ImportEntries);
    }

    if(auto *Relocations = Module.getAuxData<gtirb::schema::Relocations>())
    {
        relations::insert(Program, "relocation", *Relocations);
    }
}

void PeDataDirectoryLoader(const gtirb::Module &Module, souffle::SouffleProgram &Program)
{
    if(auto *DataDirectories = Module.getAuxData<gtirb::schema::PeDataDirectories>())
    {
        relations::insert(Program, "pe_data_directory", *DataDirectories);
    }

    if(auto *DebugData = Module.getAuxData<gtirb::schema::PeDebugData>())
    {
        relations::insert(Program, "pe_debug_data", *DebugData);
    }

    if(auto *LoadConfig = Module.getAuxData<gtirb::schema::PeLoadConfig>())
    {
        if(auto *Relation = Program.getRelation("pe_load_config"))
        {
            for(const auto [Name, Value] : *LoadConfig)
            {
                souffle::tuple Row(Relation);
                Row << Name << Value;
                Relation->insert(Row);
            }
        }
    }
}

namespace souffle
{
    souffle::tuple &operator<<(souffle::tuple &T, const relations::PeExportEntry &ExportEntry)
    {
        auto &[Address, Ordinal, Name] = ExportEntry;
        T << Address << Ordinal << Name;
        return T;
    }

    souffle::tuple &operator<<(souffle::tuple &T, const relations::PeImportEntry &ImportEntry)
    {
        auto &[Address, Ordinal, Function, Library] = ImportEntry;
        T << Address << Ordinal << Function << Library;
        return T;
    }

    souffle::tuple &operator<<(souffle::tuple &T, const relations::PeDataDirectory &DataDirectory)
    {
        auto &[Type, Address, Size] = DataDirectory;
        T << Type << Address << Size;
        return T;
    }
} // namespace souffle
