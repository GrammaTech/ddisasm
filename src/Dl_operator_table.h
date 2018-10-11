//===- Dl_operator_table.h --------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2018 GrammaTech, Inc.  All rights reserved.
//
//  This project is sponsored by the Office of Naval Research, One Liberty
//  Center, 875 N. Randolph Street, Arlington, VA 22203 under contract #
//  N68335-17-C-0700.  The content of the information does not necessarily
//  reflect the position or policy of the Government and no official
//  endorsement should be inferred.
//
//===----------------------------------------------------------------------===//
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
#include <vector>

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
    std::vector<std::pair<Dl_operator, int64_t>> get_operators_of_type(operator_type type) const;


};

#endif /* SRC_DL_OPERATOR_TABLE_H_ */
