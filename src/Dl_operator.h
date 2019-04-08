//===- Dl_operator.h --------------------------------------------*- C++ -*-===//
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

#ifndef SRC_DL_OPERATOR_H_
#define SRC_DL_OPERATOR_H_

#include <cstdint>
#include <string>

enum operator_type
{
    NONE,
    REG,
    IMMEDIATE,
    INDIRECT
};

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

    Dl_operator(operator_type type = operator_type::NONE, std::string reg1 = "none",
                std::string reg2 = "none", std::string reg3 = "none", int64_t offset = 0,
                int64_t multiplier = 1, int64_t = 0, short size = 0)
        : type(type),
          reg1(reg1),
          reg2(reg2),
          reg3(reg3),
          multiplier(multiplier),
          offset(offset),
          size(size)
    {
    }

    operator_type get_type() const;
    // for debugging purposes
    std::string print() const;

    std::string print_tabs(int64_t id) const;
};

struct compare_operators
{
    bool operator()(const Dl_operator& op1, const Dl_operator& op2) const;
};

#endif /* SRC_DL_OPERATOR_H_ */
