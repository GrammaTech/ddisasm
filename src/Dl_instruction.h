//===- Dl_instruction.h -----------------------------------------*- C++ -*-===//
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

#ifndef SRC_DL_INSTRUCTION_H_
#define SRC_DL_INSTRUCTION_H_

#include <cstdint>
#include <string>
#include <vector>

class Dl_instruction
{
public:
    int64_t address;
    long size;
    std::string prefix;
    std::string name;
    std::vector<int64_t> op_codes;

    Dl_instruction() : address(0), size(0), prefix(), name(), op_codes(){};

    Dl_instruction(int64_t address, long size, const std::string& prefix, const std::string& name,
                   std::vector<int64_t> op_codes)
        : address(address), size(size), prefix(prefix), name(name), op_codes(op_codes){};

    std::string result_tabs();
};

#endif /* SRC_DL_INSTRUCTION_H_ */
