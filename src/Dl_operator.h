//===- Dl_operator.h --------------------------------------------*- C++ -*-===//
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
 * Dl_operator.h
 *
 *  Created on: Feb 1, 2018
 *      Author: afloresmontoya
 */

#ifndef SRC_DL_OPERATOR_H_
#define SRC_DL_OPERATOR_H_

#include <string>
#include <cstdint>

enum operator_type{NONE, REG,IMMEDIATE,INDIRECT};


class Dl_operator
{
private:


public:
    operator_type type;
    std::string reg1;
    std::string reg2;
    std::string reg3;
    int64_t multiplier;
    int64_t offset;
    short size;

    Dl_operator(operator_type type=operator_type::NONE,
                std::string reg1="none",
                std::string reg2="none",
                std::string reg3="none",
                int64_t offset=0,
                int64_t multiplier=1,
                int64_t=0,
                short size=0):
                    type(type),
                    reg1(reg1),
                    reg2(reg2),
                    reg3(reg3),
                    multiplier(multiplier),
                    offset(offset),
                    size(size){}

    operator_type get_type() const;
    // for debugging purposes
    std::string print() const;

    std::string print_tabs(int64_t id) const;
};

struct compare_operators{
    bool operator() (const Dl_operator&  op1,const Dl_operator&  op2) const;
};


#endif /* SRC_DL_OPERATOR_H_ */
