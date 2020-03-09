//===- GtirbZeroBuilder.h ---------------------------------------*- C++ -*-===//
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

#include <gtirb/gtirb.hpp>

#ifndef GTIRB_ZERO_BUILDER_H_
#define GTIRB_ZERO_BUILDER_H_

struct ElfSymbolInfo
{
    uint64_t Size;
    std::string Type;
    std::string Scope;
    std::string Visibility;
    uint64_t SectionIndex;
};

template <>
struct gtirb::auxdata_traits<ElfSymbolInfo>
{
    static std::string type_id();
    static void toBytes(const ElfSymbolInfo& Object, to_iterator It);
    static from_iterator fromBytes(ElfSymbolInfo& Object, from_iterator It);
};

using SectionProperties = std::tuple<uint64_t, uint64_t>;
bool isAllocatedSection(const gtirb::FileFormat format, int flags);
bool isNonZeroDataSection(const gtirb::FileFormat format, const SectionProperties& s);
bool isExeSection(const gtirb::FileFormat format, const SectionProperties& s);

gtirb::IR* buildZeroIR(const std::string& filename, gtirb::Context& context);

#endif // GTIRB_ZERO_BUILDER_H_
