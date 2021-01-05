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

using ElfRelocation = std::tuple<uint64_t, std::string, std::string, int64_t>;
using ElfSymbolInfo = std::tuple<uint64_t, std::string, std::string, std::string, uint64_t>;
using ElfSymbolTabIdxInfo = std::vector<std::tuple<std::string, uint64_t>>;
using SectionProperties = std::tuple<uint64_t, uint64_t>;
using ElfDynamicEntry = std::tuple<std::string, uint64_t>;

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

        /// \brief Auxiliary data for extra symbol info.
        struct ElfSymbolTabIdxInfoAD
        {
            static constexpr const char* Name = "elfSymbolTabIdxInfo";
            typedef std::map<gtirb::UUID, ElfSymbolTabIdxInfo> Type;
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

        /// \brief Auxiliary data describing a binary's relocation records
        struct Relocations
        {
            static constexpr const char* Name = "relocations";
            typedef std::set<ElfRelocation> Type;
        };

        /// \brief Auxiliary data describing a binary's dynamic entries
        struct DynamicEntries
        {
            static constexpr const char* Name = "dynamicEntries";
            typedef std::set<ElfDynamicEntry> Type;
        };

        /// \brief Auxiliary data covering data object encoding specifiers.
        struct Encodings
        {
            static constexpr const char* Name = "encodings";
            typedef std::map<gtirb::UUID, std::string> Type;
        };

        /// \brief Auxiliary data mapping a section index to a section UUID.
        struct ElfSectionIndex
        {
            static constexpr const char* Name = "elfSectionIndex";
            typedef std::map<uint64_t, gtirb::UUID> Type;
        };

        /// \brief Auxiliary data covering ELF section properties.
        struct ElfSectionProperties
        {
            static constexpr const char* Name = "elfSectionProperties";
            typedef std::map<gtirb::UUID, std::tuple<uint64_t, uint64_t>> Type;
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

        /// \brief Auxiliary data that stores the size of symbolic expressions.
        struct SymbolicExpressionSizes
        {
            static constexpr const char* Name = "symbolicExpressionSizes";
            typedef std::map<gtirb::Offset, uint64_t> Type;
        };

        /// \brief Auxiliary data that stores the version of ddisasm used to
        // produce the GTIRB.
        struct DdisasmVersion
        {
            static constexpr const char* Name = "ddisasmVersion";
            typedef std::string Type;
        };
    } // namespace schema
} // namespace gtirb

#endif // DDISASM_AUXDATASCHEMA_H
