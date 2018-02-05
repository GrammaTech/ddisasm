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
#include "Datalog_visitor_x64.h"


#include <vector>
#include <cstdint>


class Dl_data{
    int64_t ea;
    int64_t content;
public:
    Dl_data(int64_t ea, int64_t content):
        ea(ea),
        content(content){}
    std::string result_tabs();
};

class Dl_decoder
{
private:
    Dl_operator_table op_dict;
    std::vector<Dl_instruction> instructions;
    std::vector<int64_t> invalids;
    std::vector<Dl_data> data;
public:
    void decode_section(char* buff,uint64_t size,int64_t ea);
    void store_data_section(char* buff,uint64_t size,int64_t ea,uint64_t min_address,uint64_t max_address);

    void print_instructions(std::ofstream& fbuf);
    void print_operators_of_type(operator_type type,std::ofstream& fbuf);
    void print_invalids(std::ofstream& fbuf);
    void print_data(std::ofstream& fbuf);

};


#endif /* SRC_DL_DECODER_H_ */
