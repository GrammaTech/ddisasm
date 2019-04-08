//===- Dl_operator_table.cpp ------------------------------------*- C++ -*-===//
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

#include "Dl_operator_table.h"

int64_t Dl_operator_table::add_to_dict(op_dict& dict, Dl_operator op)
{
    auto pair = dict.find(op);
    if(pair != dict.end())
        return (pair->second);
    else
    {
        dict[op] = curr_index;
        return curr_index++;
    }
}

int64_t Dl_operator_table::add(Dl_operator op)
{
    return add_to_dict(dicts[op.get_type()], op);
}
void Dl_operator_table::print_operators_of_type(operator_type type, std::ofstream& fbuf)
{
    for(auto pair : dicts[type])
    {
        fbuf << pair.first.print_tabs(pair.second) << std::endl;
    }
}

std::vector<std::pair<Dl_operator, int64_t>> Dl_operator_table::get_operators_of_type(
    operator_type type) const
{
    std::vector<std::pair<Dl_operator, int64_t>> result;
    for(const auto& pair : dicts[type])
    {
        result.push_back(pair);
    }
    return result;
}
