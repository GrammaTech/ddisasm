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

class BinaryReader
{
public:
    using symbol =
        std::tuple<uint64_t, uint64_t, std::string, std::string, std::uint64_t, std::string>;
    using section = std::tuple<std::string, uint64_t, uint64_t>;
    using relocation = std::tuple<uint64_t, std::string, std::string, uint64_t>;

    virtual ~BinaryReader() = default;
    virtual bool is_valid() = 0;
    virtual uint64_t get_max_address() = 0;
    virtual uint64_t get_min_address() = 0;

    virtual std::vector<section> get_sections() = 0;
    virtual std::string get_binary_type() = 0;
    virtual uint64_t get_entry_point() = 0;
    virtual std::vector<symbol> get_symbols() = 0;

    virtual std::vector<BinaryReader::relocation> get_relocations() = 0;

    virtual std::vector<std::string> get_libraries() = 0;
    virtual std::vector<std::string> get_library_paths() = 0;

    virtual std::optional<std::tuple<std::vector<uint8_t>, uint64_t>>
    get_section_content_and_address(const std::string& name) = 0;
};
#endif /* BINARY_READER_H_ */