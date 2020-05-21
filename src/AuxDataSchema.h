//===- AuxDataSchema.h ------------------------------------------*- C++ -*-===//
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

#ifndef DDISASM_AUXDATASCHEMA_H
#define DDISASM_AUXDATASCHEMA_H

#include <gtirb/gtirb.hpp>
#include <map>
#include <string>
#include <tuple>
#include <vector>
#include "BinaryReader.h"
#include "GtirbZeroBuilder.h"

/// \file AuxDataSchema.h
/// \ingroup AUXDATA_GROUP
/// \brief AuxData types used by ddisasm that are not sanctioned.
/// \see AUXDATA_GROUP

namespace gtirb
{
    namespace schema
    {
        /// \brief Auxiliary data for extra symbol info.
        struct ElfSymbolInfoAD
        {
            static constexpr const char* Name = "elfSymbolInfo";
            typedef std::map<gtirb::UUID, ElfSymbolInfo> Type;
        };

        /// \brief Auxiliary data describing a binary's type.
        struct BinaryType
        {
            static constexpr const char* Name = "binaryType";
            typedef std::vector<std::string> Type;
        };

        /// \brief Auxiliary data that maps code blocks to integers
        /// representing strongly connected components in the
        /// intra-procedural CFG. (The CFG without taking into account
        /// call and return edges.)
        struct Sccs
        {
            static constexpr const char* Name = "SCCs";
            typedef std::map<gtirb::UUID, int64_t> Type;
        };

        /// \brief Auxiliary data that keeps track of info associated
        /// with each individual appearance of a symbolic operand.
        struct SymbolicOperandInfoAD {
            static constexpr const char* Name = "symbolicOperandInfo";
            typedef std::map<gtirb::Addr, std::tuple<uint64_t, std::string>> Type;
        };

        /// \brief Auxiliary data describing a binary's relocation records
        struct Relocations
        {
            static constexpr const char* Name = "relocations";
            typedef std::set<InitialAuxData::Relocation> Type;
        };

        /// \brief Auxiliary data covering data object encoding specifiers.
        struct Encodings
        {
            static constexpr const char* Name = "encodings";
            typedef std::map<gtirb::UUID, std::string> Type;
        };

        struct FlaggedSections
        {
            static constexpr const char* Name = "FlaggedSections";
            typedef std::map<gtirb::UUID, gtirb::UUID> Type;
        };

        /// \brief Auxiliary data covering ELF section properties.
        struct ElfSectionProperties
        {
            static constexpr const char* Name = "elfSectionProperties";
            typedef std::map<gtirb::UUID, std::tuple<uint64_t, uint64_t>> Type;
        };

        struct AllElfSectionProperties
        {
            static constexpr const char* Name = "allElfSectionProperties";
            typedef std::map<gtirb::UUID, std::tuple<uint64_t, uint64_t>> Type;
        };

        struct DWARFElfSectionProperties
        {
            static constexpr const char* Name = "DWARFElfSectionProperties";
            typedef std::map<gtirb::UUID, std::tuple<uint64_t, uint64_t>> Type;
        };



        /// \brief Auxiliary data covering PE section properties.
        struct PeSectionProperties
        {
            static constexpr const char* Name = "peSectionProperties";
            typedef std::map<gtirb::UUID, uint64_t> Type;
        };

        /// \brief Auxiliary data covering cfi directives.
        struct CfiDirectives
        {
            static constexpr const char* Name = "cfiDirectives";
            typedef std::map<
                gtirb::Offset,
                std::vector<std::tuple<std::string, std::vector<int64_t>, gtirb::UUID>>>
                Type;
        };

        /// \brief Auxiliary data that includes names of necessary libraries.
        struct Libraries
        {
            static constexpr const char* Name = "libraries";
            typedef std::vector<std::string> Type;
        };

        /// \brief Auxiliary data that includes names of necessary library paths.
        struct LibraryPaths
        {
            static constexpr const char* Name = "libraryPaths";
            typedef std::vector<std::string> Type;
        };

        /// \brief Auxiliary data that tracks data directories for windows binaries.
        struct DataDirectories
        {
            static constexpr const char* Name = "dataDirectories";
            typedef std::vector<std::tuple<std::string, uint64_t, uint64_t>> Type;
        };

    } // namespace schema
} // namespace gtirb

#endif // DDISASM_AUXDATASCHEMA_H
