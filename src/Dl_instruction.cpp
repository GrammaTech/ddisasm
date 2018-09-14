//===- Dl_instruction.cpp ---------------------------------------*- C++ -*-===//
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
    for (size_t i=0;i<4;++i){
        if(i<op_codes.size())
            o<<"\t"<< op_codes[i];
        else
            o<<"\t"<< 0;
    }
    return o.str();
}
