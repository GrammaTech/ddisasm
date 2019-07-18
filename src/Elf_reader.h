//===- Elf_reader.h ---------------------------------------------*- C++ -*-===//
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

#ifndef ELF_READER_H_
#define ELF_READER_H_

#include <elf.h>
#include <fstream>
#include <tuple>
#include <vector>
#include "BinaryReader.h"

class Elf_reader : public BinaryReader
{
public:
    using symbol =
        std::tuple<uint64_t, uint64_t, std::string, std::string, std::uint64_t, std::string>;
    using section = std::tuple<std::string, uint64_t, uint64_t>;
    using relocation = std::tuple<uint64_t, std::string, std::string, uint64_t>;

private:
    std::ifstream file;
    bool valid;
    Elf64_Ehdr header;
    std::vector<Elf64_Shdr> sections;
    std::vector<std::string> section_names;

    std::vector<Elf64_Sym> symbols;
    std::vector<std::string> symbol_names;

    std::vector<Elf64_Sym> dyn_symbols;
    std::vector<std::string> dyn_symbol_names;

    std::vector<Elf64_Rela> dyn_relocations;
    std::vector<Elf64_Rela> other_relocations;

    std::vector<Elf64_Dyn> dynamic_entries;

    bool check_type();
    void read_header();
    void read_sections();
    void read_symbols();
    void read_dynamic_symbols();
    void read_relocations();
    void read_dynamic_section();

    std::string get_relocation_type(int type);
    void print_symbol_table(std::ostream& stream, std::vector<Elf64_Sym>& symbol_table,
                            std::vector<std::string>& symbol_name_table);
    void add_symbols_from_table(std::vector<symbol>& out,
                                const std::vector<Elf64_Sym>& symbol_table,
                                const std::vector<std::string>& symbol_name_table);

    int get_section_index(const std::string& name);

public:
    Elf_reader(std::string filename);
    ~Elf_reader();

    bool is_valid() override;
    uint64_t get_max_address() override;
    uint64_t get_min_address() override;

    std::vector<section> get_sections() override;
    std::string get_binary_type() override;
    uint64_t get_entry_point() override;
    std::vector<symbol> get_symbols() override;
    std::vector<relocation> get_relocations() override;

    std::vector<std::string> get_libraries() override;
    std::vector<std::string> get_library_paths() override;

    std::optional<std::tuple<std::vector<uint8_t>, uint64_t>> get_section(
        const std::string& name) override;
};
#endif /* ELF_READER_H_ */
