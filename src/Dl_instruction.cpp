/*
 * Dl_instruction.cpp
 *
 *  Created on: Feb 2, 2018
 *      Author: afloresmontoya
 */

#include <datalog_disasm/src/Dl_instruction.h>
#include <sstream>



std::string Dl_instruction::result_tabs(){
    std::ostringstream o;
    o<<address<<"\t"<<size<<"\t"<<prefix<<"\t"<<name;
    for (size_t i=0;i<3;++i){
        if(i<op_codes.size())
            o<<"\t"<< op_codes[i];
        else
            o<<"\t"<< 0;
    }
    return o.str();
}
