//===- Elf_reader.cpp -------------------------------------------*- C++ -*-===//
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

#include "Elf_reader.h"
#include <algorithm>
#include <cstring>
#include <iostream>
using namespace std;

Elf_reader::Elf_reader(string filename)
    : file(filename, ios::in | ios::binary),
      valid(false),
      header(),
      sections(),
      section_names(),
      symbols(),
      symbol_names()
{
    read_header();
    valid = file.is_open() && check_type();
    if(valid)
    {
        read_sections();
        read_symbols();
        read_dynamic_symbols();
        read_relocations();
    }
}

Elf_reader::~Elf_reader()
{
    if(file.is_open())
        file.close();
}

void Elf_reader::read_header()
{
    if(file.is_open())
    {
        file.seekg(0, ios::beg);
        file.read((char*)(&header), sizeof(Elf64_Ehdr));
    }
}

bool Elf_reader::check_type()
{
    const unsigned char magic_num[] = {ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3};
    if(memcmp(header.e_ident, magic_num, sizeof(magic_num)) != 0)
    {
        cerr << "Not an ELF executable\n";
        return false;
    }
    if(header.e_ident[EI_CLASS] != ELFCLASS64)
    {
        std::cerr << "Not ELF-64\n";
        return false;
    }
    return true;
}
void Elf_reader::read_sections()
{
    // moving to the sections
    file.seekg(header.e_shoff, ios::beg);
    // read all sections
    for(int i = 0; i < header.e_shnum; i++)
    {
        Elf64_Shdr sect;
        file.read((char*)(&sect), sizeof(Elf64_Shdr));
        sections.push_back(sect);
    }

    // read the names
    Elf64_Shdr* SecName_section = &sections[header.e_shstrndx];
    for(int i = 0; i < header.e_shnum; i++)
    {
        // position in the begining of the name
        file.seekg((SecName_section->sh_offset + sections[i].sh_name), ios::beg);
        std::stringstream buff;
        read_string(buff);
        ;
        section_names.push_back(buff.str());
    }
}
void Elf_reader::read_dynamic_symbols()
{
    int dynsym_indx = 0, dynstr_indx = 0;

    // get the indices of the sections
    for(int i = 0; i < header.e_shnum; i++)
    {
        if(section_names[i] == ".dynsym")
            dynsym_indx = i;
        if(section_names[i] == ".dynstr")
            dynstr_indx = i;
    }
    // dynamic table
    int num_symbols = sections[dynsym_indx].sh_size / sizeof(Elf64_Sym);
    file.seekg(sections[dynsym_indx].sh_offset, ios::beg);
    for(int i = 0; i < num_symbols; i++)
    {
        Elf64_Sym symbol;
        file.read((char*)(&symbol), sizeof(Elf64_Sym));
        dyn_symbols.push_back(symbol);
    }

    // read the names
    for(auto symbol : dyn_symbols)
    {
        std::stringstream buff;
        file.seekg((sections[dynstr_indx].sh_offset + symbol.st_name), ios::beg);
        read_string(buff);
        ;
        dyn_symbol_names.push_back(buff.str());
    }
}
void Elf_reader::read_symbols()
{
    int symtab_indx = 0, strtab_indx = 0;

    // get the indices of the sections
    for(int i = 0; i < header.e_shnum; i++)
    {
        if(section_names[i] == ".symtab")
            symtab_indx = i;
        if(section_names[i] == ".strtab")
            strtab_indx = i;
    }
    // other symbols
    int num_symbols = sections[symtab_indx].sh_size / sizeof(Elf64_Sym);
    file.seekg(sections[symtab_indx].sh_offset, ios::beg);
    for(int i = 0; i < num_symbols; i++)
    {
        Elf64_Sym symbol;
        file.read((char*)(&symbol), sizeof(Elf64_Sym));
        symbols.push_back(symbol);
    }

    // read the names
    for(auto symbol : symbols)
    {
        file.seekg((sections[strtab_indx].sh_offset + symbol.st_name), ios::beg);
        std::stringstream buff;
        read_string(buff);
        std::string name = buff.str();
        // Ignore the symbol version for now
        name = name.substr(0, name.find_first_of('@'));
        symbol_names.push_back(name);
    }
}

void Elf_reader::read_string(std::stringstream& str)
{
    char character;
    while(true)
    {
        file.read(&character, sizeof(char));
        if(!character)
            return;
        str << character;
    }
}

void Elf_reader::read_relocations()
{
    if(int reladyn_indx = get_section_index(".rela.dyn"); reladyn_indx != -1)
    {
        int num_rela = sections[reladyn_indx].sh_size / sizeof(Elf64_Rela);
        file.seekg(sections[reladyn_indx].sh_offset, ios::beg);
        for(int i = 0; i < num_rela; i++)
        {
            Elf64_Rela relocation;
            file.read((char*)(&relocation), sizeof(Elf64_Rela));
            relocations.push_back(relocation);
        }
    }

    if(int relaplt_indx = get_section_index(".rela.plt"); relaplt_indx != -1)
    {
        int num_rela = sections[relaplt_indx].sh_size / sizeof(Elf64_Rela);
        file.seekg(sections[relaplt_indx].sh_offset, ios::beg);
        for(int i = 0; i < num_rela; i++)
        {
            Elf64_Rela relocation;
            file.read((char*)(&relocation), sizeof(Elf64_Rela));
            relocations.push_back(relocation);
        }
    }
}

bool Elf_reader::is_valid()
{
    return valid;
}
void Elf_reader::print_entry_point(ostream& stream)
{
    stream << header.e_entry << endl;
}

uint64_t Elf_reader::get_entry_point()
{
    return header.e_entry;
}

bool Elf_reader::print_entry_point_to_file(const string& filename)
{
    ofstream file(filename, ios::out | ios::binary);
    if(file.is_open())
    {
        print_entry_point(file);
        file.close();
        return true;
    }
    else
    {
        return false;
    }
}

bool Elf_reader::print_binary_type_to_file(const string& filename)
{
    static string binary_type_names[6] = {"NONE", /* No file type */
                                          "REL",  /* Relocatable file */
                                          "EXEC", /* Executable file */
                                          "DYN",  /* Shared object file */
                                          "CORE", /* Core file */
                                          "NUM"}; /* Number of defined types */
    ofstream file(filename, ios::out | ios::binary);
    if(file.is_open())
    {
        if(header.e_type < 6)
            file << binary_type_names[header.e_type];
        else
            file << "OTHER";
        file.close();
        return true;
    }
    else
    {
        return false;
    }
}

string Elf_reader::get_binary_type()
{
    static string binary_type_names[] = {
        "NONE", /* No file type */
        "REL",  /* Relocatable file */
        "EXEC", /* Executable file */
        "DYN",  /* Shared object file */
        "CORE", /* Core file */
        "NUM",  /* Number of defined types */
    };
    if(header.e_type < 6)
        return binary_type_names[header.e_type];
    return "OTHER";
}

void Elf_reader::print_sections(ostream& stream)
{
    auto sect_it = sections.begin();
    auto sect_names_it = section_names.begin();
    while(sect_it != sections.end())
    {
        if(*sect_names_it != "" && sect_it->sh_flags & SHF_ALLOC)
            stream << *sect_names_it << '\t' << sect_it->sh_size << '\t' << sect_it->sh_addr
                   << endl;
        ++sect_it;
        ++sect_names_it;
    }
}

vector<Elf_reader::section> Elf_reader::get_sections()
{
    auto sect_it = sections.begin();
    auto sect_names_it = section_names.begin();
    vector<section> result;
    while(sect_it != sections.end())
    {
        if(*sect_names_it != "" && sect_it->sh_flags & SHF_ALLOC)
            result.emplace_back(*sect_names_it, sect_it->sh_size, sect_it->sh_addr);
        ++sect_it;
        ++sect_names_it;
    }
    return result;
}

bool Elf_reader::print_sections_to_file(const string& filename)
{
    ofstream file(filename, ios::out | ios::binary);
    if(file.is_open())
    {
        print_sections(file);
        file.close();
        return true;
    }
    else
    {
        return false;
    }
}

string get_symbol_scope_str(unsigned char info)
{
    switch(ELF64_ST_BIND(info))
    {
        case STB_LOCAL:
            return "LOCAL";
        case STB_GLOBAL:
            return "GLOBAL";
        case STB_WEAK:
            return "WEAK";
        case STB_NUM:
            return "NUM";
        default:
            return "OTHER";
    }
}
string get_symbol_type_str(unsigned char type)
{
    switch(ELF64_ST_TYPE(type))
    {
        case STT_NOTYPE:
            return "NOTYPE";
        case STT_OBJECT:
            return "OBJECT";
        case STT_FUNC:
            return "FUNC";
        case STT_SECTION:
            return "SECTION";
        case STT_FILE:
            return "FILE";
        case STT_COMMON:
            return "COMMON";
        case STT_TLS:
            return "TLS";
        case STT_NUM:
            return "NUM";
        default:
            return "OTHER";
    }
}

void Elf_reader::print_symbol_table(ostream& stream, std::vector<Elf64_Sym>& symbol_table,
                                    std::vector<string>& symbol_name_table)
{
    auto symbol_it = symbol_table.begin();
    auto symbol_names_it = symbol_name_table.begin();
    while(symbol_it != symbol_table.end())
    {
        if(*symbol_names_it != "")
            stream << symbol_it->st_value << '\t' << symbol_it->st_size << '\t'
                   << get_symbol_type_str(symbol_it->st_info) << '\t'
                   << get_symbol_scope_str(symbol_it->st_info) << '\t' << symbol_it->st_shndx
                   << '\t' << *symbol_names_it << endl;

        ++symbol_it;
        ++symbol_names_it;
    }
}

void Elf_reader::add_symbols_from_table(std::vector<symbol>& out,
                                        const std::vector<Elf64_Sym>& symbol_table,
                                        const std::vector<string>& symbol_name_table)
{
    auto symbol_it = symbol_table.begin();
    auto symbol_names_it = symbol_name_table.begin();
    while(symbol_it != symbol_table.end())
    {
        if(*symbol_names_it != "")
            out.emplace_back(
                symbol_it->st_value, symbol_it->st_size, get_symbol_type_str(symbol_it->st_info),
                get_symbol_scope_str(symbol_it->st_info), symbol_it->st_shndx, *symbol_names_it);

        ++symbol_it;
        ++symbol_names_it;
    }
}

void Elf_reader::print_symbols(ostream& stream)
{
    print_symbol_table(stream, symbols, symbol_names);
    print_symbol_table(stream, dyn_symbols, dyn_symbol_names);
}

vector<Elf_reader::symbol> Elf_reader::get_symbols()
{
    vector<symbol> result;
    add_symbols_from_table(result, symbols, symbol_names);
    add_symbols_from_table(result, dyn_symbols, dyn_symbol_names);

    return result;
}
bool Elf_reader::print_symbols_to_file(const string& filename)
{
    ofstream file(filename, ios::out | ios::binary);
    if(file.is_open())
    {
        print_symbols(file);
        file.close();
        return true;
    }
    else
    {
        return false;
    }
}
string Elf_reader::get_relocation_type(int type)
{
    static string type_names[40] = {
        "R_X86_64_NONE",
        "R_X86_64_64",              /* Direct 64 bit  */
        "R_X86_64_PC32",            /* PC relative 32 bit signed */
        "R_X86_64_GOT32",           /* 32 bit GOT entry */
        "R_X86_64_PLT32",           /* 32 bit PLT address */
        "R_X86_64_COPY",            /* Copy symbol at runtime */
        "R_X86_64_GLOB_DAT",        /* Create GOT entry */
        "R_X86_64_JUMP_SLOT",       /* Create PLT entry */
        "R_X86_64_RELATIVE",        /* Adjust by program base */
        "R_X86_64_GOTPCREL",        /* 32 bit signed PC relative
   offset to GOT */
        "R_X86_64_32",              /* Direct 32 bit zero extended */
        "R_X86_64_32S",             /* Direct 32 bit sign extended */
        "R_X86_64_16",              /* Direct 16 bit zero extended */
        "R_X86_64_PC16",            /* 16 bit sign extended pc relative */
        "R_X86_64_8",               /* Direct 8 bit sign extended  */
        "R_X86_64_PC8",             /* 8 bit sign extended pc relative */
        "R_X86_64_DTPMOD64",        /* ID of module containing symbol */
        "R_X86_64_DTPOFF64",        /* Offset in module's TLS block */
        "R_X86_64_TPOFF64",         /* Offset in initial TLS block */
        "R_X86_64_TLSGD",           /* 32 bit signed PC relative offset
                 to two GOT entries for GD symbol */
        "R_X86_64_TLSLD",           /* 32 bit signed PC relative offset
       to two GOT entries for LD symbol */
        "R_X86_64_DTPOFF32",        /* Offset in TLS block */
        "R_X86_64_GOTTPOFF",        /* 32 bit signed PC relative offset
   to GOT entry for IE symbol */
        "R_X86_64_TPOFF32",         /* Offset in initial TLS block */
        "R_X86_64_PC64",            /* PC relative 64 bit */
        "R_X86_64_GOTOFF64",        /* 64 bit offset to GOT */
        "R_X86_64_GOTPC32",         /* 32 bit signed pc relative
   offset to GOT */
        "R_X86_64_GOT64",           /* 64-bit GOT entry offset */
        "R_X86_64_GOTPCREL64",      /* 64-bit PC relative offset
    to GOT entry */
        "R_X86_64_GOTPC64",         /* 64-bit PC relative offset to GOT */
        "R_X86_64_GOTPLT64",        /* like GOT64, says PLT entry needed */
        "R_X86_64_PLTOFF64",        /* 64-bit GOT relative offset
      to PLT entry */
        "R_X86_64_SIZE32",          /* Size of symbol plus 32-bit addend */
        "R_X86_64_SIZE64",          /* Size of symbol plus 64-bit addend */
        "R_X86_64_GOTPC32_TLSDESC", /* GOT offset for TLS descriptor.  */
        "R_X86_64_TLSDESC_CALL",    /* Marker for call through TLS
descriptor.  */
        "R_X86_64_TLSDESC",         /* TLS descriptor.  */
        "R_X86_64_IRELATIVE",       /* Adjust indirectly by program base */
        "R_X86_64_RELATIVE64",      /* 64-bit adjust by program base */
        "R_X86_64_NUM"};
    return type_names[type];
}
void Elf_reader::print_relocations(ostream& stream)
{
    // this depends on reading the .dynsym first, before the .symtab when reading symbols
    for(auto relocation : relocations)
    {
        int symbol_index = ELF64_R_SYM(relocation.r_info);
        int type = ELF64_R_TYPE(relocation.r_info);
        stream << relocation.r_offset << '\t' << get_relocation_type(type) << '\t'
               << dyn_symbol_names[symbol_index] << '\t' << relocation.r_addend << endl;
    }
}
bool Elf_reader::print_relocations_to_file(const string& filename)
{
    ofstream file(filename, ios::out | ios::binary);
    if(file.is_open())
    {
        print_relocations(file);
        file.close();
        return true;
    }
    else
    {
        return false;
    }
}

vector<Elf_reader::relocation> Elf_reader::get_relocations()
{
    // this depends on reading the .dynsym first, before the .symtab when reading symbols
    vector<relocation> result;
    for(auto relocation : relocations)
    {
        int symbol_index = ELF64_R_SYM(relocation.r_info);
        int type = ELF64_R_TYPE(relocation.r_info);
        result.emplace_back(relocation.r_offset, get_relocation_type(type),
                            dyn_symbol_names[symbol_index], relocation.r_addend);
    }
    return result;
}

int Elf_reader::get_section_index(const string& name)
{
    for(size_t i = 0; i < section_names.size(); ++i)
    {
        if(name == section_names[i])
            return i;
    }
    return -1;
}

uint64_t Elf_reader::get_min_address()
{
    uint64_t min_address = UINTMAX_MAX;
    for(auto section : sections)
    {
        if(section.sh_type == SHT_PROGBITS || section.sh_type == SHT_NOBITS)
            min_address = min(min_address, section.sh_addr);
    }
    return min_address;
}
uint64_t Elf_reader::get_max_address()
{
    uint64_t max_address = 0;
    for(auto section : sections)
    {
        if(section.sh_type == SHT_PROGBITS || section.sh_type == SHT_NOBITS)
            max_address = max(max_address, section.sh_addr + section.sh_size);
    }
    return max_address;
}

char* Elf_reader::get_section(const string& name, uint64_t& size, Elf64_Addr& initial_addr)
{
    int index = get_section_index(name);
    if(index == -1)
    {
        size = 0;
        return nullptr;
    }
    if(sections[index].sh_type == SHT_NOBITS)
    {
        size = 0;
        return nullptr;
    }
    size = sections[index].sh_size;
    initial_addr = sections[index].sh_addr;
    char* buff;
    try
    {
        buff = new char[size];
    }
    catch(std::bad_alloc& ba)
    {
        std::cerr << "bad_alloc caught: " << ba.what() << "trying to allocate for " << name << endl;
        return nullptr;
    }
    file.seekg((sections[index].sh_offset), ios::beg);
    file.read(buff, size);
    return buff;
}

char* Elf_reader::get_section(const string& name, uint64_t& size)
{
    Elf64_Addr initial_addr;
    return get_section(name, size, initial_addr);
}
