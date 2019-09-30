//===- BinaryReader.h ------------------------------------------*- C++ -*-===//
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

#ifndef BINARY_READER_H_
#define BINARY_READER_H_
#include <optional>
#include <string>
#include <vector>
#include "gtirb/gtirb.hpp"

namespace InitialAuxData
{
    struct Symbol
    {
        uint64_t address;
        uint64_t size;
        std::string type;
        std::string scope;
        uint64_t sectionIndex;
        std::string name;
    };

    constexpr bool operator<(const Symbol &LHS, const Symbol &RHS) noexcept
    {
        return std::tie(LHS.address, LHS.size, LHS.type, LHS.scope, LHS.sectionIndex, LHS.name)
               < std::tie(RHS.address, RHS.size, RHS.type, RHS.scope, RHS.sectionIndex, RHS.name);
    }

    struct Section
    {
        std::string name;
        uint64_t size;
        uint64_t address;
        uint64_t type;
        uint64_t flags;
    };

    constexpr bool operator<(const Section &LHS, const Section &RHS) noexcept
    {
        return std::tie(LHS.name, LHS.size, LHS.address, LHS.type, LHS.flags)
               < std::tie(RHS.name, RHS.size, RHS.address, RHS.type, RHS.flags);
    }

    struct Relocation
    {
        uint64_t address;
        std::string type;
        std::string name;
        int64_t addend;
    };

    constexpr bool operator<(const Relocation &LHS, const Relocation &RHS) noexcept
    {
        return std::tie(LHS.address, LHS.type, LHS.name, LHS.addend)
               < std::tie(RHS.address, RHS.type, RHS.name, RHS.addend);
    }

} // namespace InitialAuxData

template <>
struct gtirb::auxdata_traits<InitialAuxData::Relocation>
{
    static std::string type_id()
    {
        return "InitialRelocation";
    }

    static void toBytes(const InitialAuxData::Relocation &Object, to_iterator It)
    {
        auxdata_traits<uint64_t>::toBytes(Object.address, It);
        auxdata_traits<std::string>::toBytes(Object.type, It);
        auxdata_traits<std::string>::toBytes(Object.name, It);
        auxdata_traits<int64_t>::toBytes(Object.addend, It);
    }

    static from_iterator fromBytes(InitialAuxData::Relocation &Object, from_iterator It)
    {
        It = auxdata_traits<uint64_t>::fromBytes(Object.address, It);
        It = auxdata_traits<std::string>::fromBytes(Object.type, It);
        It = auxdata_traits<std::string>::fromBytes(Object.name, It);
        It = auxdata_traits<int64_t>::fromBytes(Object.addend, It);
        return It;
    }
};

class BinaryReader
{
public:
    virtual ~BinaryReader() = default;
    virtual bool is_valid() = 0;
    virtual uint64_t get_max_address() = 0;
    virtual uint64_t get_min_address() = 0;

    virtual gtirb::FileFormat get_binary_format() = 0;
    virtual std::set<InitialAuxData::Section> get_sections() = 0;

    virtual std::string get_binary_type() = 0;
    virtual uint64_t get_entry_point() = 0;
    virtual std::set<InitialAuxData::Symbol> get_symbols() = 0;

    virtual std::set<InitialAuxData::Relocation> get_relocations() = 0;

    virtual std::vector<std::string> get_libraries() = 0;
    virtual std::vector<std::string> get_library_paths() = 0;

    virtual std::optional<std::tuple<std::vector<uint8_t>, uint64_t>>
    get_section_content_and_address(const std::string &name) = 0;
};

#endif /* BINARY_READER_H_ */