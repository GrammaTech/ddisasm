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
private:
    int64_t address;
    long size;
    std::string prefix;
    std::string name;
    std::vector<int64_t> op_codes;
public:

    Dl_instruction():
        address(0),
        size(0),
        prefix(),
        name(),
        op_codes(){};

    Dl_instruction(int64_t address,long size,std::string prefix,std::string name,std::vector<int64_t> op_codes):
        address(address),
        size(size),
        prefix(prefix),
        name(name),
        op_codes(op_codes){};

    std::string result_tabs();
};

#endif /* SRC_DL_INSTRUCTION_H_ */
