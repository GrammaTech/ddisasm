//===- Dl_instruction.h -----------------------------------------*- C++ -*-===//
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
 * Dl_instruction.h
 *
 *  Created on: Feb 2, 2018
 *      Author: afloresmontoya
 */

#ifndef SRC_DL_INSTRUCTION_H_
#define SRC_DL_INSTRUCTION_H_

#include <vector>
#include <cstdint>
#include <string>

class Dl_instruction
{
public:
    int64_t address;
    long size;
    std::string prefix;
    std::string name;
    std::vector<int64_t> op_codes;

    Dl_instruction():
        address(0),
        size(0),
        prefix(),
        name(),
        op_codes(){};

    Dl_instruction(int64_t address,long size, const std::string& prefix, const std::string& name,std::vector<int64_t> op_codes):
        address(address),
        size(size),
        prefix(prefix),
        name(name),
        op_codes(op_codes){};

    std::string result_tabs();
};

#endif /* SRC_DL_INSTRUCTION_H_ */
