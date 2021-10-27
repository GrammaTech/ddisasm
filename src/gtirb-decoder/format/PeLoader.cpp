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

void PeSymbolLoader(const gtirb::Module &Module, DatalogProgram &Program)
{
    if(auto *ExportEntries = Module.getAuxData<gtirb::schema::ExportEntries>())
    {
        Program.insert("pe_export_entry", *ExportEntries);
    }

    if(auto *ImportEntries = Module.getAuxData<gtirb::schema::ImportEntries>())
    {
        Program.insert("pe_import_entry", *ImportEntries);
    }
}

void PeDataDirectoryLoader(const gtirb::Module &Module, DatalogProgram &Program)
{
    if(auto *DataDirectories = Module.getAuxData<gtirb::schema::PeDataDirectories>())
    {
        Program.insert("pe_data_directory", *DataDirectories);
    }

    if(auto *DebugData = Module.getAuxData<gtirb::schema::PeDebugData>())
    {
        Program.insert("pe_debug_data", *DebugData);
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
