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
        std::string visibility;
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

    struct DataDirectory
    {
        uint64_t address;
        uint64_t size;
        std::string type;
    };

    struct ImportEntry
    {
        uint64_t iat_address;
        int64_t ordinal;
        std::string function;
        std::string library;
    };

    struct ExportEntry
    {
        uint64_t address;
        uint16_t ordinal;
        std::string name;
    };
} // namespace InitialAuxData

template <>
struct gtirb::auxdata_traits<InitialAuxData::Relocation>
{
    static std::string type_name()
    {
        return "InitialRelocation";
    }

    static void toBytes(const InitialAuxData::Relocation &Object, to_iterator It)
    {
        auxdata_traits<std::tuple<uint64_t, std::string, std::string, int64_t>>::toBytes(
            std::make_tuple(Object.address, Object.type, Object.name, Object.addend), It);
    }

    static from_iterator fromBytes(InitialAuxData::Relocation &Object, from_iterator It)
    {
        std::tuple<uint64_t, std::string, std::string, int64_t> Tuple;
        auxdata_traits<std::tuple<uint64_t, std::string, std::string, int64_t>>::fromBytes(Tuple,
                                                                                           It);
        Object.address = std::get<0>(Tuple);
        Object.type = std::get<1>(Tuple);
        Object.name = std::get<2>(Tuple);
        Object.addend = std::get<3>(Tuple);
        return It;
    }
};

template <>
struct gtirb::auxdata_traits<InitialAuxData::DataDirectory>
{
    static std::string type_name()
    {
        return "DataDirectory";
    }

    static void toBytes(const InitialAuxData::DataDirectory &Object, to_iterator It)
    {
        auxdata_traits<std::tuple<uint64_t, uint64_t, std::string>>::toBytes(
            std::make_tuple(Object.address, Object.size, Object.type), It);
    }

    static from_iterator fromBytes(InitialAuxData::DataDirectory &Object, from_iterator It)
    {
        std::tuple<uint64_t, uint64_t, std::string> Tuple;
        auxdata_traits<std::tuple<uint64_t, uint64_t, std::string>>::fromBytes(Tuple, It);
        Object.address = std::get<0>(Tuple);
        Object.size = std::get<1>(Tuple);
        Object.type = std::get<2>(Tuple);
        return It;
    }
};

template <>
struct gtirb::auxdata_traits<InitialAuxData::ImportEntry>
{
    static std::string type_name()
    {
        return "ImportEntry";
    }

    static void toBytes(const InitialAuxData::ImportEntry &Object, to_iterator It)
    {
        auxdata_traits<std::tuple<uint64_t, int64_t, std::string, std::string>>::toBytes(
            std::make_tuple(Object.iat_address, Object.ordinal, Object.function, Object.library),
            It);
    }

    static from_iterator fromBytes(InitialAuxData::ImportEntry &Object, from_iterator It)
    {
        std::tuple<uint64_t, int64_t, std::string, std::string> Tuple;
        auxdata_traits<std::tuple<uint64_t, int64_t, std::string, std::string>>::fromBytes(Tuple,
                                                                                           It);
        Object.iat_address = std::get<0>(Tuple);
        Object.ordinal = std::get<1>(Tuple);
        Object.function = std::get<2>(Tuple);
        Object.library = std::get<3>(Tuple);
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
    virtual std::set<gtirb::SectionFlag> get_section_flags(
        const InitialAuxData::Section &section) = 0;

    virtual std::string get_binary_type() = 0;
    virtual uint64_t get_entry_point() = 0;
    virtual uint64_t get_base_address() = 0;
    virtual std::set<InitialAuxData::Symbol> get_symbols() = 0;

    virtual std::set<InitialAuxData::Relocation> get_relocations() = 0;

    virtual std::vector<std::string> get_libraries() = 0;
    virtual std::vector<std::string> get_library_paths() = 0;
    virtual std::vector<InitialAuxData::DataDirectory> get_data_directories() = 0;
    virtual std::vector<InitialAuxData::ImportEntry> get_import_entries() = 0;
    virtual std::vector<InitialAuxData::ExportEntry> get_export_entries() = 0;

    virtual std::optional<std::tuple<std::vector<uint8_t>, uint64_t>>
    get_section_content_and_address(const std::string &name, uint64_t addr) = 0;
};

#endif /* BINARY_READER_H_ */
