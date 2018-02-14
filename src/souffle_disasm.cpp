//============================================================================
// Name        : souffle_disasm.cpp
// Author      : Antonio Flores-Montoya
// Version     :
// Copyright   :
// Description :
//============================================================================

#include "Dl_decoder.h"
#include "Elf_reader.h"

// for now we do not use souffle directly
//#include "souffle/SouffleInterface.h"
#include "gtr/src/lang/gtr_config.h"

#include <boost/program_options.hpp>
#include <cctype>
#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <algorithm>

//---------------------
// VSA_DLL_DEP HACK!!!
// <isa>_show depends on tsl_rtg_<isa>, which uses memcasecmp and should
// rightfully depend on feature 'string'.  However, the situation with Windows'
// vsa_tsl_<isa>.dll/swyxana_<isa>.lib currently prevents us from adding that
// dependence, as it leads to linker multiply-defined symbol errors.
// As a (very ugly) workaround, we add this dummy dependence on memcasecmp,
// with a corresponding dummy SCons dependence on 'string', to let this link
// successfully without changing tsl_rtg_<isa>'s dependences.
#include "gtr/src/string/string_ops.h"
int dummy_hack(const void * lhs, size_t lsize, const void * rhs, size_t rsize) {
    return memcasecmp(lhs, lsize, rhs, rsize);
}
// end VSA_DLL_DEP HACK
namespace po = boost::program_options;
using namespace std;

int main(int argc, char** argv) {
    po::options_description desc("Allowed options");
    desc.add_options()
                            ("help", "produce help message")
                            ("file", po::value<string>(), "the binary to analyze")
                            ("sect", po::value<vector<string> >(), "sections to decode")
                            ("data_sect", po::value<vector<string> >(), "data sections to consider")
                            ("dir", po::value<string>(), "output directory");

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);


    if (vm.count("help")) {
        cout << desc << "\n";
        return 1;
    }
    string file;
    if (vm.count("file") ) {
        file=vm["file"].as<string>();
    } else {
        cout << "No input file was provided.\n";
        cout << desc << "\n";
        return 1;
    }
    vector<string> sections;
    if (vm.count("sect") ) {
        sections=vm["sect"].as<vector<string> >();
    } else {
        cout << "No sections were provided.\n";
        cout << desc << "\n";
        return 1;
    }
    vector<string> data_sections;
    if (vm.count("data_sect") ) {
        data_sections=vm["data_sect"].as<vector<string> >();
    }
    string directory;
    if (vm.count("dir")) {
        directory=vm["dir"].as<string>();
    }else{
        cout << "Please provide an output directory.\n";
        cout << desc << "\n";
        return 1;
    }

    ios_base::openmode filemask=ios::out;
    //    filemask=filemask | std::ios_base::app;

    Elf_reader elf(file);
    if(!elf.is_valid()){
        cerr<<"There was a problem loading the binary file "<<file<<endl;
        return 1;
    }

    cout<<"Valid binary\n";
    cout<<"Saving sections\n";
    elf.print_sections_to_file(directory+"section.facts");
    cout<<"Saving symbols\n";
    elf.print_symbols_to_file(directory+"symbol.facts");
    cout<<"Saving relocations\n";
    elf.print_relocations_to_file(directory+"relocation.facts");
    Dl_decoder decoder;

    uint64_t min_address=UINTMAX_MAX;
    uint64_t max_address=0;
    for(auto section_name:sections){
        int64_t size;
        uint64_t address;
        char* buff=elf.get_section(section_name,size,address);
        if(buff!=nullptr){
            cout<<"Decoding section "<<section_name<<" of size "<<size <<endl;
            min_address=min(min_address,address);
            max_address=max(max_address,address+size);
            decoder.decode_section(buff,size,address);
            delete[] buff;
        }else
            cerr<<"Section "<<section_name<<" not found"<<endl;

    }
    for(auto section_name:data_sections){
        int64_t size;
        uint64_t address;
        char* buff=elf.get_section(section_name,size,address);
        if(buff!=nullptr){
            cout<<"Storing data section "<<section_name<<" of size "<<size <<endl;
            decoder.store_data_section(buff,size,address,min_address,max_address);
            delete[] buff;
        }else
            cerr<<"Section "<<section_name<<" not found"<<endl;

    }
    cout<<"Saving results in directory: "<<directory<<endl;

    cout<<"Saving instruction "<<endl;
    ofstream instructions_file(directory+"instruction.facts",filemask);
    decoder.print_instructions(instructions_file);
    instructions_file.close();

    cout<<"Saving data "<<endl;
    ofstream data_file(directory+"data_address.facts",filemask);
    decoder.print_data(data_file);
    data_file.close();

    ofstream data_bytes_file(directory+"data_byte.facts",filemask);
    decoder.print_data_bytes(data_bytes_file);
    data_bytes_file.close();

    cout<<"Saving invalids "<<endl;
    ofstream invalids_file(directory+"invalid_op_code.facts",filemask);
    decoder.print_invalids(invalids_file);
    invalids_file.close();

    cout<<"Saving operators "<<endl;

    ofstream op_regdirect_file(directory+"op_regdirect.facts",filemask);
    decoder.print_operators_of_type(operator_type::REG,op_regdirect_file);
    op_regdirect_file.close();

    ofstream op_immediate_file(directory+"op_immediate.facts",filemask);
    decoder.print_operators_of_type(operator_type::IMMEDIATE,op_immediate_file);
    op_immediate_file.close();

    ofstream op_indirect_file(directory+"op_indirect.facts",filemask);;
    decoder.print_operators_of_type(operator_type::INDIRECT,op_indirect_file);
    op_indirect_file.close();

    cout<<"Done "<<endl;

    return 0;

}

