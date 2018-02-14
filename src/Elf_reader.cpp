/*
 * Elf_reader.cpp
 *
 *  Created on: Feb 4, 2018
 *      Author: aeflores
 */

#include "Elf_reader.h"
#include <cstring>
#include <iostream>
using namespace std;

Elf_reader::Elf_reader(string filename):
							file(filename, ios::in|ios::binary),
							valid(false),
							header(),
							sections(),
							section_names(),
							symbols(),
							symbol_names(){

	read_header();
	valid=file.is_open() && check_type();
	if(valid){
		read_sections();
		read_symbols();
		read_dynamic_symbols();
		read_relocations();
	}
}

Elf_reader::~Elf_reader(){
	if (file.is_open())
		file.close();
}

void Elf_reader::read_header(){
	if(file.is_open()){
		file.seekg (0, ios::beg);
		file.read((char*)(&header), sizeof(Elf64_Ehdr));
	}
}

bool Elf_reader::check_type(){
	const unsigned char magic_num[] = {ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3};
	if (memcmp(header.e_ident, magic_num, sizeof(magic_num)) != 0) {
		cerr << "Not an ELF executable\n";
		return false;
	}
	if (header.e_ident[EI_CLASS] != ELFCLASS64) {
		std::cerr << "Not ELF-64\n";
		return false;
	}
	return true;

}
void Elf_reader::read_sections(){

	//moving to the sections
	file.seekg (header.e_shoff, ios::beg);
	// read all sections
	for(int i=0;i<header.e_shnum; i++){
		Elf64_Shdr sect;
		file.read((char*)(&sect), sizeof(Elf64_Shdr));
		sections.push_back(sect);
	}

	//read the names
	Elf64_Shdr* SecName_section= &sections[header.e_shstrndx];
	const int buff_size=100;
	char buff[buff_size];
	for(int i=0;i<header.e_shnum; i++){
		//position in the begining of the name
		file.seekg ((SecName_section->sh_offset+sections[i].sh_name), ios::beg);
		file.read(buff, buff_size);
		section_names.push_back(buff);
	}

}
void Elf_reader::read_dynamic_symbols(){
	int dynsym_indx=0, dynstr_indx=0;

	//get the indices of the sections
	for(int i=0;i<header.e_shnum; i++){
		if(section_names[i]==".dynsym")
			dynsym_indx=i;
		if(section_names[i]==".dynstr")
				dynstr_indx=i;

	}
	//dynamic table
	int num_symbols=sections[dynsym_indx].sh_size/sizeof(Elf64_Sym);
	file.seekg(sections[dynsym_indx].sh_offset, ios::beg);
	for(int i=0;i<num_symbols; i++){
		Elf64_Sym symbol;
		file.read((char*)(&symbol), sizeof(Elf64_Sym));
		dyn_symbols.push_back(symbol);
	}

	//read the names
	const int buff_size=100;
	char buff[buff_size];
	for(auto symbol:dyn_symbols){
		file.seekg((sections[dynstr_indx].sh_offset+symbol.st_name), ios::beg);
		file.read(buff, buff_size);
		dyn_symbol_names.push_back(buff);
	}

}
void Elf_reader::read_symbols(){
	int symtab_indx=0,strtab_indx=0;


	//get the indices of the sections
	for(int i=0;i<header.e_shnum; i++){
		if(section_names[i]==".symtab")
			symtab_indx=i;
		if(section_names[i]==".strtab")
			strtab_indx=i;
	}
	//other symbols
	int num_symbols=sections[symtab_indx].sh_size/sizeof(Elf64_Sym);
	file.seekg(sections[symtab_indx].sh_offset, ios::beg);
	for(int i=0;i<num_symbols; i++){
		Elf64_Sym symbol;
		file.read((char*)(&symbol), sizeof(Elf64_Sym));
		symbols.push_back(symbol);
	}

	//read the names
	const int buff_size=100;
	char buff[buff_size];
	for(auto symbol:symbols){
		file.seekg((sections[strtab_indx].sh_offset+symbol.st_name), ios::beg);
		file.read(buff, buff_size);
		symbol_names.push_back(buff);
	}

}

void Elf_reader::read_relocations(){

	int reladyn_indx=get_section_index(".rela.dyn");
	int relaplt_indx=get_section_index(".rela.plt");


	int num_rela=sections[reladyn_indx].sh_size/sizeof(Elf64_Rela);
	file.seekg(sections[reladyn_indx].sh_offset, ios::beg);
	for(int i=0;i<num_rela; i++){
		Elf64_Rela relocation;
		file.read((char*)(&relocation), sizeof(Elf64_Rela));
		relocations.push_back(relocation);
	}

	num_rela=sections[relaplt_indx].sh_size/sizeof(Elf64_Rela);
	file.seekg(sections[relaplt_indx].sh_offset, ios::beg);
	for(int i=0;i<num_rela; i++){
		Elf64_Rela relocation;
		file.read((char*)(&relocation), sizeof(Elf64_Rela));
		relocations.push_back(relocation);
	}
}

bool Elf_reader::is_valid(){
	return valid;
}
void Elf_reader::print_sections(ostream& stream){
	auto sect_it=sections.begin();
	auto sect_names_it=section_names.begin();
	while(sect_it!=sections.end()){
	    if(*sect_names_it!="")
		stream<< *sect_names_it<<'\t'
				<<  sect_it->sh_size <<'\t'
				<<  sect_it->sh_addr<< endl;
            ++sect_it;
            ++sect_names_it;
	}
}
/*
void Elf_reader::add_sections_to_souffle(souffle::Relation* rel){
	auto sect_it=sections.begin();
	auto sect_names_it=section_names.begin();
	while(sect_it!=sections.end()){
		souffle::tuple tuple(rel);
		tuple<< *sect_names_it
				<<  sect_it->sh_size
				<<  sect_it->sh_addr;
		rel->insert(tuple);
		++sect_it;
		++sect_names_it;
	}
}
*/
bool Elf_reader::print_sections_to_file(const string& filename){
	ofstream file(filename,ios::out|ios::binary);
	if(file.is_open()){
		print_sections(file);
		file.close();
		return true;
	}else{
		return false;
	}
}

string get_symbol_scope_str(unsigned char info){
    switch(ELF64_ST_BIND(info)){
    case STB_LOCAL:
        return "LOCAL";
    case STB_GLOBAL:
        return "GLOBAL";
    case STB_WEAK:
        return "WEAK";
    case	STB_NUM:
        return "NUM";
    default:
        return "OTHER";
    }
}
string get_symbol_type_str(unsigned char type){
	switch(ELF64_ST_TYPE(type)){
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

void Elf_reader::print_symbols(ostream& stream){
    auto symbol_it=symbols.begin();
    auto symbol_names_it=symbol_names.begin();
    while(symbol_it!=symbols.end()){
        if(*symbol_names_it!="")
            stream<< symbol_it->st_value <<'\t'
            << symbol_it->st_size <<'\t'
            <<  get_symbol_type_str(symbol_it->st_info) <<'\t'
            <<  get_symbol_scope_str(symbol_it->st_info) <<'\t'
            << *symbol_names_it<<endl;

        ++symbol_it;
        ++symbol_names_it;
    }
}

/*
void Elf_reader::add_symbols_to_souffle(souffle::Relation* rel){
	auto symbol_it=symbols.begin();
	auto symbol_names_it=symbol_names.begin();
	while(symbol_it!=symbols.end()){
		souffle::tuple tuple(rel);
		tuple<< *symbol_names_it
				<<  symbol_it->st_info
				<< symbol_it->st_value
				<< symbol_it->st_size;
		rel->insert(tuple);
		++symbol_it;
		++symbol_names_it;
	}
}
*/
bool Elf_reader::print_symbols_to_file(const string& filename){
	ofstream file(filename,ios::out|ios::binary);
	if(file.is_open()){
		print_symbols(file);
		file.close();
		return true;
	}else{
		return false;
	}

}

void Elf_reader::print_relocations(ostream& stream){
    //this depends on reading the .dynsym first, before the .symtab when reading symbols
    for(auto relocation: relocations){
        int symbol_index=ELF64_R_SYM(relocation.r_info);
        stream<< relocation.r_offset <<'\t'
            << dyn_symbol_names[symbol_index] <<'\t'
            << relocation.r_addend <<endl;
    }
}
bool Elf_reader::print_relocations_to_file(const string& filename){
	ofstream file(filename,ios::out|ios::binary);
	if(file.is_open()){
		print_relocations(file);
		file.close();
		return true;
	}else{
		return false;
	}

}


int Elf_reader::get_section_index(const string& name){
	for(size_t i=0;i<section_names.size();++i){
		if(name==section_names[i])
			return i;
	}
	return -1;
}


char* Elf_reader::get_section(const string& name,int64_t & size,Elf64_Addr& initial_addr){
	int index=get_section_index(name);
	if(index!=-1){
		size=sections[index].sh_size;
		initial_addr=sections[index].sh_addr;
		char* buff= new char[size];
		file.seekg((sections[index].sh_offset), ios::beg);
		file.read(buff, size);
		return buff;
	}else{
		size=0;
		return nullptr;
	}
}
char* Elf_reader::get_section(const string& name,int64_t & size){
	Elf64_Addr addr;
	return get_section(name,size,addr);
}

bool Elf_reader::extract_section(const string& name, const string& filename){
	int64_t size;
	char* buff=get_section(name,size);
	if(buff!=nullptr){
		ofstream file_sect(filename,ios::out|ios::binary);
		if(file_sect.is_open()){
			file_sect.write(buff,size);
			file.close();
			delete[] buff;
			return true;
		}else{
			cerr<<"Problem opening the file "<<filename<<endl;
			delete[] buff;
			return false;
		}
	}{
		cerr<<"The section"<<name<<" was not found"<<endl;
		return false;
	}

}

