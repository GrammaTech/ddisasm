//============================================================================
// Name        : souffle_disasm.cpp
// Author      : Antonio Flores-Montoya
// Version     :
// Copyright   :
// Description :
//============================================================================

#include "Datalog_visitor_x64.h"
#include "Dl_operator_table.h"

#include "gtr/src/lang/gtr_config.h"
#include "isal/x64/decoderff.hpp"
#include "souffle/SouffleInterface.h"

#include <cctype>
#include <iostream>
#include <sstream>
#include <fstream>
#include <string>


typedef csuint64 ea_int_t;
//#define NBYTES_ON_FAILURE(buf) 1
//#define TO_ASM(instr) X64genPPrinter::to_asm(instr, mode)

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

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Give me some argument" << std::endl;
        exit(1);
    }

    X64genDecoderFF::initialize();
    // initialize the first EA with the address argument, if provided
    ea_int_t ea = 0;
    std::ios_base::openmode filemask=std::ios::out;
    if (argc >= 3 && !strncasecmp(argv[2], "-address=", 9))
        ea = strtoull(argv[2] + 9, 0, 0);

    bool is_data(false);
    if (argc >= 4 && !strncasecmp(argv[3], "-data",5))
        is_data = true;
    if (argc >= 4 && !strncasecmp(argv[3], "-append",7))
        filemask=filemask | std::ios_base::app;

    std::filebuf fbuf;
    fbuf.open(argv[1], std::ios::in | std::ios::binary);
    size_t buf_size = 102400;
    char * buf = new char[buf_size];
    std::streamsize nbytes_left = fbuf.sgetn(buf, buf_size);
    char * bufptr = buf;

    std::string directory=argv[1];
    size_t found=directory.find_last_of("/\\");
    directory= directory.substr(0,found)+'/';
    std::cout<<"Saving results in directory: "<<directory<<std::endl;
    std::ofstream instruction_file;


    instruction_file.open(directory+"instruction.facts",filemask);
    std::ofstream invalid_file;
    invalid_file.open(directory+"invalid.facts",filemask);

    Dl_operator_table op_dict;
    while (nbytes_left > 0) {
        unsigned int nbytes_decoded;
        // safe to cast here since nbytes_left is in the range (0-buf_size]
        if (is_data) {
            uint64_t * data= (uint64_t*)(bufptr);
            std::cout<<"data("<<ea<<","<<*data<<")"<<std::endl;
        } else {
            ConcTSLInterface::instructionRefPtr instr = X64genDecoderFF::decode(
                    bufptr, ea, static_cast<unsigned int>(nbytes_left),
                    &nbytes_decoded, IADC_LongMode);

            if (instr.is_empty()) {
                invalid_file << ea << std::endl;
            } else {
                Datalog_visitor_x64 visitor(ea,static_cast<long>(nbytes_decoded));
                instr->accept(visitor);
                //std::cout << instr << std::endl;
                visitor.collect_operands(op_dict);
               // std::cout << visitor.result() << std::endl;
                instruction_file << visitor.result_tabs() << std::endl;
                //std::cout << X64genPPrinter::to_souffle(ea,static_cast<long>(nbytes_decoded),instr,op_dict) << std::endl;

            }
        }
        ++ea;
        ++bufptr;
        --nbytes_left;
        if (nbytes_left == 0) {
            nbytes_left = fbuf.sgetn(buf, buf_size);
            bufptr = buf;
        }
    }
    instruction_file.close();
    invalid_file.close();
    std::cout << "operators "<< std::endl;
    op_dict.print(directory,filemask);
    delete buf;
    return 0;
}

