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
#include <vector>
#include "souffle/SouffleInterface.h"

class Elf_reader
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
    bool check_type();
    void read_header();
    void read_sections();
    void read_symbols();
    void read_dynamic_symbols();
    void read_relocations();
    std::string get_relocation_type(int type);
    void print_symbol_table(std::ostream& stream, std::vector<Elf64_Sym>& symbol_table,
                            std::vector<std::string>& symbol_name_table);
    void add_symbols_from_table(std::vector<symbol>& out,
                                const std::vector<Elf64_Sym>& symbol_table,
                                const std::vector<std::string>& symbol_name_table);

    int get_section_index(const std::string& name);
    void read_string(std::stringstream& str);

public:
    Elf_reader(std::string filename);
    ~Elf_reader();

    bool is_valid();
    uint64_t get_max_address();
    uint64_t get_min_address();
    void print_sections(std::ostream&);
    bool print_sections_to_file(const std::string& filename);

    std::vector<section> get_sections();

    bool print_binary_type_to_file(const std::string& filename);
    std::string get_binary_type();

    void print_entry_point(std::ostream&);
    bool print_entry_point_to_file(const std::string& filename);
    uint64_t get_entry_point();

    void print_symbols(std::ostream&);
    bool print_symbols_to_file(const std::string& filename);
    std::vector<symbol> get_symbols();

    void print_relocations(std::ostream&);
    bool print_relocations_to_file(const std::string& filename);
    std::vector<Elf_reader::relocation> get_relocations();

    char* get_section(const std::string& name, uint64_t& buff, Elf64_Addr& initial_addr);
    char* get_section(const std::string& name, uint64_t& buff);
};

#endif /* ELF_READER_H_ */
