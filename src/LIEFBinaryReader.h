//===- LIEFBinaryReader.h ------------------------------------------*- C++ -*-===//
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

#ifndef LIEF_BINARY_READER_H_
#define LIEF_BINARY_READER_H_
#include <LIEF/LIEF.hpp>
#include <gtirb/gtirb.hpp>
#include <string>
#include <vector>
#include "BinaryReader.h"

class LIEFBinaryReader : public BinaryReader
{
public:
    LIEFBinaryReader(const std::string& filename);
    ~LIEFBinaryReader() = default;
    bool is_valid() override;
    uint64_t get_max_address() override;
    uint64_t get_min_address() override;

    std::set<InitialAuxData::Section> get_sections() override;
    std::set<gtirb::SectionFlag> get_section_flags(const InitialAuxData::Section& section) override;
    gtirb::FileFormat get_binary_format() override;
    std::string get_binary_type() override;
    uint64_t get_entry_point() override;
    std::set<InitialAuxData::Symbol> get_symbols() override;
    std::set<InitialAuxData::Relocation> get_relocations() override;

    std::vector<std::string> get_libraries() override;
    std::vector<std::string> get_library_paths() override;

    std::optional<std::tuple<std::vector<uint8_t>, uint64_t>> get_section_content_and_address(
        const std::string& name) override;

private:
    std::unique_ptr<LIEF::Binary> bin;
    std::string getRelocationType(const LIEF::ELF::Relocation& entry);
};
#endif /* LIEF_BINARY_READER_H_ */
