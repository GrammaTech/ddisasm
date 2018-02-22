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

using namespace std;

void Dl_decoder::decode_section(char* buf,uint64_t size,int64_t ea){
    X64genDecoderFF::initialize();
    while (size > 0) {
        unsigned int nbytes_decoded;
        // safe to cast here since nbytes_left is in the range (0-buf_size]
        ConcTSLInterface::instructionRefPtr instr = X64genDecoderFF::decode(
                buf, ea, static_cast<unsigned int>(size),
                &nbytes_decoded, IADC_LongMode);

        if (instr.is_empty()) {
            invalids.push_back(ea);
        } else {
            Datalog_visitor_x64 visitor(ea,static_cast<long>(nbytes_decoded),&op_dict);
            instr->accept(visitor);
            instructions.push_back(move(visitor.get_instruction()));
        }

        ++ea;
        ++buf;
        --size;

    }
}

bool can_be_address(uint64_t num, uint64_t min_address, uint64_t max_address){
    return ((num>=min_address) && (num<=max_address));  //absolute address
     //     ||  (num+min_address<=max_address); //offset
}

void Dl_decoder::store_data_section(char* buf,uint64_t size,int64_t ea,uint64_t min_address,uint64_t max_address){
    while (size > 0) {
        //store the byte
        unsigned char content_byte=*buf;
        data_bytes.push_back(Dl_data<unsigned char>(ea,content_byte));

        //store the address
        if(size>=8 ){
        uint64_t content=*((int64_t*)buf);
        if (can_be_address(content,min_address,max_address))
            data.push_back(Dl_data<int64_t>(ea,content));
        }
        ++ea;
        ++buf;
        --size;

    }
}



void Dl_decoder::print_instructions(std::ofstream& fbuf){
    for(auto instruction: instructions){
        fbuf<<instruction.result_tabs()<<endl;
    }
}
void Dl_decoder::print_operators_of_type(operator_type type,ofstream& fbuf){
    op_dict.print_operators_of_type(type,fbuf);

}
void Dl_decoder::print_invalids(ofstream& fbuf){
    for(auto invalid: invalids){
        fbuf<<invalid<<endl;
    }
}

void Dl_decoder::print_data(ofstream& fbuf){
    for(auto data_item: data){
        fbuf<<data_item.result_tabs()<<endl;
    }
}
void Dl_decoder::print_data_bytes(ofstream& fbuf){
    for(auto data_item: data_bytes){
        fbuf<<data_item.result_tabs()<<endl;
    }
}

template <class Content>
std::string Dl_data<Content>::result_tabs(){
    ostringstream o;
    o<<ea<<'\t'<<static_cast<int64_t>(content);
    return o.str();
}
