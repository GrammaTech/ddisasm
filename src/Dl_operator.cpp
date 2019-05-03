//===- Dl_operator.cpp ------------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2019 GrammaTech, Inc.
//
//  This code is licensed under the GNU Affero General Public License
//  as published by the Free Software Foundation, either version 3 of
//  the License, or (at your option) any later version. See the
//  LICENSE.txt file in the project root for license terms or visit
//  https://www.gnu.org/licenses/agpl.txt.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
//  GNU Affero General Public License for more details.
//
//  This project is sponsored by the Office of Naval Research, One Liberty
//  Center, 875 N. Randolph Street, Arlington, VA 22203 under contract #
//  N68335-17-C-0700.  The content of the information does not necessarily
//  reflect the position or policy of the Government and no official
//  endorsement should be inferred.
//
//===----------------------------------------------------------------------===//

#include "Dl_operator.h"
#include <sstream>

std::string Dl_operator::print_tabs(int64_t id) const
{
    std::ostringstream o;
    switch(type)
    {
        case NONE:
        default:
            return "none";
        case REG:
            o << id << '\t' << reg1;
            return o.str();
        case IMMEDIATE:
            o << id << '\t' << offset;
            return o.str();
        case INDIRECT:
            o << id << '\t' << reg1 << '\t' << reg2 << '\t' << reg3 << '\t' << multiplier << '\t'
              << offset << '\t' << size;
            ;
            return o.str();
    }
}

operator_type Dl_operator::get_type() const
{
    return type;
}

bool compare_operators::operator()(const Dl_operator& op1, const Dl_operator& op2) const
{
    if(op1.type == op2.type)
    {
        switch(op1.type)
        {
            case NONE:
                return false;
            case REG:
                return op1.size < op2.size || (op1.size == op2.size && op1.reg1 < op2.reg1);
            case IMMEDIATE:
                return op1.size < op2.size || (op1.size == op2.size && op1.offset < op2.offset);
            case INDIRECT:

                return op1.size < op2.size || (op1.size == op2.size && op1.reg1 < op2.reg1)
                       || ((op1.size == op2.size) && (op1.reg1 == op2.reg1)
                           && (op1.reg2 < op2.reg2))
                       || ((op1.size == op2.size) && (op1.reg1 == op2.reg1)
                           && (op1.reg2 == op2.reg2) && (op1.reg3 < op2.reg3))
                       || ((op1.size == op2.size) && (op1.reg1 == op2.reg1)
                           && (op1.reg2 == op2.reg2) && (op1.reg3 == op2.reg3)
                           && (op1.offset < op2.offset))
                       || ((op1.size == op2.size) && (op1.reg1 == op2.reg1)
                           && (op1.reg2 == op2.reg2) && (op1.reg3 == op2.reg3)
                           && (op1.offset == op2.offset) && (op1.multiplier < op2.multiplier));
        }
    }
    else
    {
        return op1.type < op2.type;
    }
    return false;
}
