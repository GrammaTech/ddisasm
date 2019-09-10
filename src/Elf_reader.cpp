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
#include <assert.h>
#include <algorithm>
#include <cstring>
#include <functional>
#include <iostream>
#include <sstream>

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
        read_dynamic_section();
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
        cerr << "Not ELF-64\n";
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
        string name;
        getline(file, name, '\0');
        section_names.push_back(name);
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
        file.seekg((sections[dynstr_indx].sh_offset + symbol.st_name), ios::beg);
        string name;
        getline(file, name, '\0');
        dyn_symbol_names.push_back(name);
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
        string name;
        getline(file, name, '\0');
        // Ignore the symbol version for now
        name = name.substr(0, name.find_first_of('@'));
        symbol_names.push_back(name);
    }
}

void Elf_reader::read_relocations()
{
    for(size_t section_index = 0; section_index < sections.size(); section_index++)
    {
        if(sections[section_index].sh_type == SHT_RELA)
        {
            int num_rela = sections[section_index].sh_size / sizeof(Elf64_Rela);
            file.seekg(sections[section_index].sh_offset, ios::beg);
            for(int i = 0; i < num_rela; i++)
            {
                Elf64_Rela relocation;
                file.read((char*)(&relocation), sizeof(Elf64_Rela));
                if(section_names[section_index] == ".rela.dyn"
                   || section_names[section_index] == ".rela.plt")
                    dyn_relocations.push_back(relocation);
                else
                    other_relocations.push_back(relocation);
            }
        }
    }
}

void Elf_reader::read_dynamic_section()
{
    for(size_t section_index = 0; section_index < sections.size(); section_index++)
    {
        if(sections[section_index].sh_type == SHT_DYNAMIC)
        {
            int num_entries = sections[section_index].sh_size / sizeof(Elf64_Dyn);
            file.seekg(sections[section_index].sh_offset, ios::beg);
            for(int i = 0; i < num_entries; i++)
            {
                Elf64_Dyn dynamic_entry;
                file.read((char*)(&dynamic_entry), sizeof(Elf64_Dyn));
                dynamic_entries.push_back(dynamic_entry);
            }
        }
    }
}

bool Elf_reader::is_valid()
{
    return valid;
}

uint64_t Elf_reader::get_entry_point()
{
    return header.e_entry;
}

gtirb::FileFormat Elf_reader::get_binary_format()
{
    return gtirb::FileFormat::ELF;
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

vector<InitialAuxData::Section> Elf_reader::get_sections()
{
    auto sect_it = sections.begin();
    auto sect_names_it = section_names.begin();
    vector<InitialAuxData::Section> result;
    while(sect_it != sections.end())
    {
        if(*sect_names_it != "")
            result.push_back({*sect_names_it, sect_it->sh_size, sect_it->sh_addr, sect_it->sh_type,
                              sect_it->sh_flags});
        ++sect_it;
        ++sect_names_it;
    }
    return result;
}

vector<InitialAuxData::Section> Elf_reader::get_code_sections()
{
    vector<InitialAuxData::Section> sections = get_sections();
    auto isExeSection = [](InitialAuxData::Section& s) { return s.flags & SHF_EXECINSTR; };
    sections.erase(remove_if(begin(sections), end(sections), not_fn(isExeSection)), end(sections));
    return sections;
}

vector<InitialAuxData::Section> Elf_reader::get_non_zero_data_sections()
{
    vector<InitialAuxData::Section> sections = get_sections();
    auto isNonZeroDataSection = [](InitialAuxData::Section& s) {
        bool is_allocated = s.flags & SHF_ALLOC;
        bool is_not_executable = !(s.flags & SHF_EXECINSTR);
        // SHT_NOBITS is not considered here because it is for data sections but without initial
        // data (zero initialized)
        bool is_non_zero_program_data = s.type == SHT_PROGBITS || s.type == SHT_INIT_ARRAY
                                        || s.type == SHT_FINI_ARRAY || s.type == SHT_PREINIT_ARRAY;
        return is_allocated && is_not_executable && is_non_zero_program_data;
    };
    sections.erase(remove_if(begin(sections), end(sections), not_fn(isNonZeroDataSection)),
                   end(sections));
    return sections;
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

void Elf_reader::add_symbols_from_table(vector<InitialAuxData::Symbol>& out,
                                        const vector<Elf64_Sym>& symbol_table,
                                        const vector<string>& symbol_name_table)
{
    auto symbol_it = symbol_table.begin();
    auto symbol_names_it = symbol_name_table.begin();
    while(symbol_it != symbol_table.end())
    {
        if(*symbol_names_it != "")
            out.push_back(
                {symbol_it->st_value, symbol_it->st_size, get_symbol_type_str(symbol_it->st_info),
                 get_symbol_scope_str(symbol_it->st_info), symbol_it->st_shndx, *symbol_names_it});

        ++symbol_it;
        ++symbol_names_it;
    }
}

vector<InitialAuxData::Symbol> Elf_reader::get_symbols()
{
    vector<InitialAuxData::Symbol> result;
    add_symbols_from_table(result, symbols, symbol_names);
    add_symbols_from_table(result, dyn_symbols, dyn_symbol_names);

    return result;
}

string Elf_reader::get_relocation_type(unsigned int type)
{
    static vector<string> type_names = {
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
    if(type >= type_names.size())
        return "UNKNOWN(" + std::to_string(type) + ")";
    return type_names[type];
}

vector<InitialAuxData::Relocation> Elf_reader::get_relocations()
{
    vector<InitialAuxData::Relocation> result;
    // dynamic relocations refer to dynsym table
    for(auto relocation : dyn_relocations)
    {
        unsigned int symbol_index = ELF64_R_SYM(relocation.r_info);
        unsigned int type = ELF64_R_TYPE(relocation.r_info);
        string symbol_name;
        // relocations without a symbol have index==0
        if(symbol_index)
        {
            assert(symbol_index < dyn_symbol_names.size()
                   && "dynamic symbol table smaller than expected");
            symbol_name = dyn_symbol_names[symbol_index];
        }
        result.push_back(
            {relocation.r_offset, get_relocation_type(type), symbol_name, relocation.r_addend});
    }
    // other relocations refer to symtab
    for(auto relocation : other_relocations)
    {
        unsigned int symbol_index = ELF64_R_SYM(relocation.r_info);
        unsigned int type = ELF64_R_TYPE(relocation.r_info);
        string symbol_name;
        // relocations without a symbol have index==0
        if(symbol_index)
        {
            assert(symbol_index < symbol_names.size() && "symbol table smaller than expected");
            symbol_name = symbol_names[symbol_index];
        }
        result.push_back(
            {relocation.r_offset, get_relocation_type(type), symbol_name, relocation.r_addend});
    }
    return result;
}

vector<string> Elf_reader::get_libraries()
{
    int dynstr_indx = get_section_index(".dynstr");
    vector<string> libraries;
    for(auto dyn_entry : dynamic_entries)
    {
        if(dyn_entry.d_tag == DT_NEEDED)
        {
            file.seekg((sections[dynstr_indx].sh_offset + dyn_entry.d_un.d_val), ios::beg);
            string library;
            getline(file, library, '\0');
            libraries.push_back(library);
        }
    }
    return libraries;
}

vector<string> Elf_reader::get_library_paths()
{
    int dynstr_indx = get_section_index(".dynstr");
    vector<string> libraryPaths;
    for(auto dyn_entry : dynamic_entries)
    {
        if(dyn_entry.d_tag == DT_RPATH || dyn_entry.d_tag == DT_RUNPATH)
        {
            file.seekg((sections[dynstr_indx].sh_offset + dyn_entry.d_un.d_val), ios::beg);
            string allPaths;
            getline(file, allPaths, '\0');
            stringstream allPathsStream(allPaths);
            allPathsStream.seekg(ios::beg);
            string path;
            while(getline(allPathsStream, path, ':'))
            {
                if(!path.empty())
                    libraryPaths.push_back(path);
            }
        }
    }
    return libraryPaths;
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

optional<tuple<vector<uint8_t>, uint64_t>> Elf_reader::get_section_content_and_address(
    const string& name)
{
    int index = get_section_index(name);
    if(index == -1)
        return nullopt;
    if(sections[index].sh_type == SHT_NOBITS)
        return nullopt;

    uint64_t size = sections[index].sh_size;
    uint64_t initial_addr = sections[index].sh_addr;
    vector<uint8_t> bytes;
    bytes.resize(size);
    file.seekg((sections[index].sh_offset), ios::beg);
    file.read(reinterpret_cast<char*>(bytes.data()), size);
    return make_tuple(bytes, initial_addr);
}