//===- InternalAuxDataSchema.h ----------------------------------*- C++ -*-===//
//
//  Copyright (C) 2019 GrammaTech, Inc.
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

#ifndef DDISASM_INTERNALAUXDATASCHEMA_H
#define DDISASM_INTERNALAUXDATASCHEMA_H

#include <map>
#include <string>
#include <tuple>
#include <vector>

#include <gtirb/gtirb.hpp>

// A DataDirectory is a tuple of the form {Type, Address, Size}.
using DataDirectory = std::tuple<std::string, uint64_t, uint64_t>;

// An ImportEntry is a tuple of the form {Iat_address, Ordinal, Function, Library}.
using ImportEntry = std::tuple<uint64_t, int64_t, std::string, std::string>;

// An ExportEntry is a tuple of the form {Address, Ordinal, Name}.
using ExportEntry = std::tuple<uint64_t, int64_t, std::string>;

namespace gtirb
{
    namespace schema
    {
        /// \brief Auxiliary data covering PE section properties.
        struct PeSectionProperties
        {
            static constexpr const char* Name = "peSectionProperties";
            typedef std::map<gtirb::UUID, uint64_t> Type;
        };

        /// \brief Auxiliary data that tracks data directories for windows binaries.
        struct DataDirectories
        {
            static constexpr const char* Name = "dataDirectories";
            // Tuples of the form {Type, Address, Size}.
            typedef std::vector<std::tuple<std::string, uint64_t, uint64_t>> Type;
        };

        /// \brief Auxiliary data representing the import table of a PE file.
        struct ImportEntries
        {
            static constexpr const char* Name = "importEntries";
            // Tuples of the form {Iat_address, Ordinal, Function, Library}.
            typedef std::vector<std::tuple<uint64_t, int64_t, std::string, std::string>> Type;
        };

        /// \brief Auxiliary data for the UUIDs of imported symbols in a PE file.
        struct PeImportedSymbols
        {
            static constexpr const char* Name = "peImportedSymbols";
            typedef std::vector<gtirb::UUID> Type;
        };

        /// \brief Auxiliary data for the UUIDs of exported symbols in a PE file.
        struct PeExportedSymbols
        {
            static constexpr const char* Name = "peExportedSymbols";
            typedef std::vector<gtirb::UUID> Type;
        };
    } // namespace schema
} // namespace gtirb

#endif // DDISASM_INTERNALAUXDATASCHEMA_H
