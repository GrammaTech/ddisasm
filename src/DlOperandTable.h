//===- DlOperandTable.h -----------------------------------------*- C++ -*-===//
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

#ifndef SRC_DL_OPERATOR_TABLE_H_
#define SRC_DL_OPERATOR_TABLE_H_

#include <souffle/SouffleInterface.h>
#include <cstdint>
#include <map>
#include <variant>
#include <vector>

using ImmOp = int64_t;

using RegOp = std::string;

struct IndirectOp
{
    std::string reg1;
    std::string reg2;
    std::string reg3;
    int64_t multiplier;
    int64_t displacement;
    int size;
};

constexpr bool operator<(const IndirectOp &LHS, const IndirectOp &RHS) noexcept;
souffle::tuple &operator<<(souffle::tuple &t, const IndirectOp &op);

template <class T>
souffle::tuple &operator<<(souffle::tuple &t, const std::pair<T, uint64_t> &pair)
{
    auto &[elem, id] = pair;
    t << id << elem;
    return t;
}

class DlOperandTable
{
private:
    // we reserve 0 for empty operators
    uint64_t curr_index = 1;
    template <typename T>
    int64_t addToTable(std::map<T, uint64_t> &opTable, T op);

public:
    std::map<ImmOp, uint64_t> immTable;
    std::map<RegOp, uint64_t> regTable;
    std::map<IndirectOp, uint64_t> indirectTable;
    int64_t add(std::variant<ImmOp, RegOp, IndirectOp> op);
};

#endif /* SRC_DL_OPERATOR_TABLE_H_ */
