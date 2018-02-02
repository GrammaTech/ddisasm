/*
 * Dl_decoder.cpp
 *
 *  Created on: Feb 2, 2018
 *      Author: afloresmontoya
 */

#include "Dl_decoder.h"
#include "isal/x64/decoderff.hpp"
#include "isal/x64/x64_pp.hpp"
#include <iostream>

void Dl_decoder::decode_section(std::filebuf& fbuf,int64_t ea=0){
    X64genDecoderFF::initialize();
    size_t buf_size = 102400;
    char * buf = new char[buf_size];

    std::streamsize nbytes_left = fbuf.sgetn(buf, buf_size);
    char * bufptr = buf;

    while (nbytes_left > 0) {
        unsigned int nbytes_decoded;
        // safe to cast here since nbytes_left is in the range (0-buf_size]
        ConcTSLInterface::instructionRefPtr instr = X64genDecoderFF::decode(
                bufptr, ea, static_cast<unsigned int>(nbytes_left),
                &nbytes_decoded, IADC_LongMode);

        if (instr.is_empty()) {
            invalids.push_back(ea);
        } else {
            Datalog_visitor_x64 visitor(ea,static_cast<long>(nbytes_decoded),&op_dict);
            instr->accept(visitor);
            instructions.push_back(visitor.get_instruction());
        }

        ++ea;
        ++bufptr;
        --nbytes_left;
        if (nbytes_left == 0) {
            nbytes_left = fbuf.sgetn(buf, buf_size);
            bufptr = buf;
        }
    }
    delete [] buf;
}


void Dl_decoder::print_instructions(std::ofstream& fbuf){
    for(auto instruction: instructions){
        fbuf<<instruction.result_tabs()<<std::endl;
    }
}
void Dl_decoder::print_operators_of_type(operator_type type,std::ofstream& fbuf){
    op_dict.print_operators_of_type(type,fbuf);

}
void Dl_decoder::print_invalids(std::ofstream& fbuf){
    for(auto invalid: invalids){
        fbuf<<invalid<<std::endl;
    }
}
