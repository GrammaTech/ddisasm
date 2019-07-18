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
#include <vector>
#include <string>
#include "BinaryReader.h"

class LIEFBinaryReader : public BinaryReader
{
public:
    using symbol =
        std::tuple<uint64_t, uint64_t, std::string, std::string, std::uint64_t, std::string>;
    using section = std::tuple<std::string, uint64_t, uint64_t>;
    using relocation = std::tuple<uint64_t, std::string, std::string, uint64_t>;

    LIEFBinaryReader(std::string filename);
    ~LIEFBinaryReader() = default;
     bool is_valid() override;
     uint64_t get_max_address() override;
     uint64_t get_min_address() override;

     std::vector<BinaryReader::section> get_sections() override;
     std::string get_binary_type() override;
     uint64_t get_entry_point() override;
     std::vector<BinaryReader::symbol> get_symbols() override;

     std::vector<BinaryReader::relocation> get_relocations() override;

     std::vector<std::string> get_libraries() override;
     std::vector<std::string> get_library_paths() override;

     char* get_section(const std::string& name, uint64_t& buff, uint64_t& initial_addr) override;
     char* get_section(const std::string& name, uint64_t& buff) override;

private:
    std::unique_ptr<LIEF::Binary> bin;


};
#endif /* LIEF_BINARY_READER_H_ */