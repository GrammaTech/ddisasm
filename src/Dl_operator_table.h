/*
 * Dl_operator_table.h
 *
 *  Created on: Feb 2, 2018
 *      Author: afloresmontoya
 */

#ifndef SRC_DL_OPERATOR_TABLE_H_
#define SRC_DL_OPERATOR_TABLE_H_

#include "Dl_operator.h"

#include <string>
#include <cstdint>
#include <map>
#include <fstream>

class Dl_operator_table{
    using op_dict=std::map<Dl_operator,int64_t,compare_operators>;

private:
    op_dict dicts[operator_type::INDIRECT+1];
    int64_t curr_index;
    int64_t add_to_dict(op_dict& dict,Dl_operator op);

public:
    Dl_operator_table():
        dicts(),
        curr_index(1){}//we reserve 0 for empty operators

    int64_t add(Dl_operator op);
    void print_operators_of_type(operator_type type,std::ofstream& fbuf);
    void print(std::string directory,std::ios_base::openmode filemask);


};

#endif /* SRC_DL_OPERATOR_TABLE_H_ */
