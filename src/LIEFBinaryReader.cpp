//===- LIEFBinaryReader.cpp ------------------------------------------*- C++ -*-===//
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

#include <LIEF/LIEF.hpp>
#include "LIEFBinaryReader.h"

LIEFBinaryReader::LIEFBinaryReader(std::string filename){
  bin=  LIEF::Parser::parse(filename);
}

bool LIEFBinaryReader::is_valid() {}
uint64_t LIEFBinaryReader::get_max_address() {
    uint64_t max_address=0;
    if(auto *elf= dynamic_cast<LIEF::ELF::Binary*>(bin.get())){
        for(auto section: elf->sections()){
            if(section.type() == LIEF::ELF::ELF_SECTION_TYPES::SHT_PROGBITS || section.type() == LIEF::ELF::ELF_SECTION_TYPES::SHT_NOBITS  ){
                max_address = std::max(max_address, section.virtual_address() + section.size());
            }
        }
    }
    //TODO PE binaries
    return max_address;
}

uint64_t LIEFBinaryReader::get_min_address() {
 uint64_t min_address=UINTMAX_MAX;
    if(auto *elf= dynamic_cast<LIEF::ELF::Binary*>(bin.get())){
        for(auto section: elf->sections()){
            if(section.type() == LIEF::ELF::ELF_SECTION_TYPES::SHT_PROGBITS || section.type() == LIEF::ELF::ELF_SECTION_TYPES::SHT_NOBITS  ){
                min_address = std::min(min_address, section.virtual_address());
            }
        }
    }
    //TODO PE binaries
    return min_address;
}

std::vector<BinaryReader::section> LIEFBinaryReader::get_sections() {
    std::vector<BinaryReader::section> sectionTuples;
    for(auto section: bin->sections()){
        sectionTuples.push_back(std::make_tuple(section.name,section.size, section.offset));
    }
    return sectionTuples;
}

std::string LIEFBinaryReader::get_binary_type(){
    if(bin->is_pie())
        return "DYN";
    return "EXEC";
}

uint64_t LIEFBinaryReader::get_entry_point(){
    return bin->entrypoint();
}

std::vector<BinaryReader::symbol> LIEFBinaryReader::get_symbols() {
    std::vector<BinaryReader::symbol> symbolTuples;
    if(auto *elf= dynamic_cast<LIEF::ELF::Binary*>(bin.get())){
        for(auto symbol: elf->symbols()){
            symbolTuples.emplace_back(symbol.value(),symbol.size(),symbol.type(), symbol.binding(), symbol.section_idx, symbol.name());
        }
    }
    return symbolTuples;
}

std::vector<BinaryReader::relocation> LIEFBinaryReader::get_relocations(){

}

std::vector<std::string> LIEFBinaryReader::get_libraries(){

}

std::vector<std::string> LIEFBinaryReader::get_library_paths(){

}

char* LIEFBinaryReader::get_section(const std::string& name, uint64_t& buff, uint64_t& initial_addr) {

}

char* LIEFBinaryReader::get_section(const std::string& name, uint64_t& buff){

}
