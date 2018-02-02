//============================================================================
// Name        : souffle_disasm.cpp
// Author      : Antonio Flores-Montoya
// Version     :
// Copyright   :
// Description :
//============================================================================

#include "Dl_decoder.h"
#include "souffle/SouffleInterface.h"
#include "gtr/src/lang/gtr_config.h"

#include <boost/program_options.hpp>
#include <cctype>
#include <iostream>
#include <sstream>
#include <fstream>
#include <string>

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
                    ("sect", po::value<vector<string> >(), "sections to decode")
                    ("addr", po::value<vector<int64_t> >(), "starting addresses")
                    ("dir", po::value<string>(), "output directory");

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);
    if (vm.count("help")) {
        cout << desc << "\n";
        return 1;
    }
    vector<string> sections;
    vector<int64_t> addresses;
    if (vm.count("sect") && vm.count("addr")) {
        sections=vm["sect"].as<vector<string> >();
        addresses=vm["addr"].as<vector<int64_t> >();
        if(sections.size()!=addresses.size()){
            cout << "The number of sections and addresses does not coincide\n";
            return 1;
        }
    } else {
        cout << "No sections or addresses were provided.\n";
        cout << desc << "\n";
        return 1;
    }
    string directory;
    if (vm.count("dir")) {
        directory=vm["dir"].as<string>();

    }else{
        cout << "Please provide an output directory.\n";
        cout << desc << "\n";
        return 1;
    }

    std::ios_base::openmode filemask=std::ios::out;
    //    filemask=filemask | std::ios_base::app;

    Dl_decoder decoder;
    auto ItSections =sections.begin();
    auto ItAddresses =addresses.begin();
    while(ItSections!=sections.end()){
        std::cout<<"Decoding section "<<*ItSections<<std::endl;
        std::filebuf fbuf;
        fbuf.open(*ItSections, std::ios::in | std::ios::binary);
        decoder.decode_section(fbuf,*ItAddresses);
        fbuf.close();

        ++ItSections;
        ++ItAddresses;
    }
    std::cout<<"Saving results in directory: "<<directory<<std::endl;
    std::cout<<"Saving instruction "<<std::endl;
    std::ofstream instructions_file;
    instructions_file.open(directory+"instruction.facts",filemask);
    decoder.print_instructions(instructions_file);
    instructions_file.close();

    std::cout<<"Saving invalids "<<std::endl;
    std::ofstream invalids_file;
    invalids_file.open(directory+"invalid.facts",filemask);
    decoder.print_invalids(invalids_file);
    invalids_file.close();

    std::cout<<"Saving operators "<<std::endl;

    std::ofstream op_regdirect_file;
    op_regdirect_file.open(directory+"op_regdirect.facts",filemask);
    decoder.print_operators_of_type(operator_type::REG,op_regdirect_file);
    op_regdirect_file.close();

    std::ofstream op_immediate_file;
    op_immediate_file.open(directory+"op_immediate.facts",filemask);
    decoder.print_operators_of_type(operator_type::IMMEDIATE,op_immediate_file);
    op_immediate_file.close();

    std::ofstream op_indirect_file;
    op_indirect_file.open(directory+"op_indirect.facts",filemask);
    decoder.print_operators_of_type(operator_type::INDIRECT,op_indirect_file);
    op_indirect_file.close();

    std::cout<<"Done "<<std::endl;

    return 0;
}

