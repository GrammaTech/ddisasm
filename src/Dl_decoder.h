//===- Dl_decoder.h ---------------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2018 GrammaTech, Inc.
//
//  This code is licensed under the GPL V3 license. See the LICENSE file in the
//  project root for license terms.
//
//  This project is sponsored by the Office of Naval Research, One Liberty
//  Center, 875 N. Randolph Street, Arlington, VA 22203 under contract #
//  N68335-17-C-0700.  The content of the information does not necessarily
//  reflect the position or policy of the Government and no official
//  endorsement should be inferred.
//
//===----------------------------------------------------------------------===//
/*
 * Dl_decoder.h
 *
 *  Created on: Feb 2, 2018
 *      Author: afloresmontoya
 */

#ifndef SRC_DL_DECODER_H_
#define SRC_DL_DECODER_H_
#include "Dl_operator_table.h"
#include "Dl_operator.h"
#include "Dl_instruction.h"

#include <capstone/capstone.h>
#include <vector>
#include <cstdint>

template <class Content>
class Dl_data{
    int64_t ea;
    Content content;
public:
    Dl_data(int64_t ea, Content content):
        ea(ea),
        content(content){}
    std::string result_tabs();
};

class Dl_decoder
{
private:
    csh csHandle;
    Dl_operator_table op_dict;
    std::vector<Dl_instruction> instructions;
    std::vector<int64_t> invalids;
    std::vector<Dl_data<int64_t> > data;
    std::vector<Dl_data<unsigned char> > data_bytes;
public:
    Dl_decoder();
    void decode_section(char* buff,uint64_t size,int64_t ea);
    std::string getRegisterName(unsigned int reg);
    Dl_instruction transformInstruction(cs_insn& insn);
    Dl_operator buildOperand(const cs_x86_op& op);
    void store_data_section(char* buff,uint64_t size,int64_t ea,uint64_t min_address,uint64_t max_address);

    void print_instructions(std::ofstream& fbuf);
    void print_operators_of_type(operator_type type,std::ofstream& fbuf);
    void print_invalids(std::ofstream& fbuf);
    void print_data(std::ofstream& fbuf);
    void print_data_bytes(std::ofstream& fbuf);

};


#endif /* SRC_DL_DECODER_H_ */
