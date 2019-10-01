//===- DlOperandTable.cpp ---------------------------------------*- C++ -*-===//
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

#include "DlOperandTable.h"

constexpr bool operator<(const IndirectOp &LHS, const IndirectOp &RHS) noexcept
{
    return std::tie(LHS.reg1, LHS.reg2, LHS.reg3, LHS.multiplier, LHS.displacement, LHS.size)
           < std::tie(RHS.reg1, RHS.reg2, RHS.reg3, RHS.multiplier, RHS.displacement, RHS.size);
}

souffle::tuple &operator<<(souffle::tuple &t, const IndirectOp &op)
{
    t << op.reg1 << op.reg2 << op.reg3 << op.multiplier << op.displacement << op.size;
    return t;
}

template <typename T>
int64_t DlOperandTable::addToTable(std::map<T, uint64_t> &opTable, T op)
{
    auto pair = opTable.find(op);
    if(pair != opTable.end())
        return (pair->second);
    else
    {
        opTable[op] = curr_index;
        return curr_index++;
    }
}

int64_t DlOperandTable::add(std::variant<ImmOp, RegOp, IndirectOp> op)
{
    if(auto *imm = std::get_if<ImmOp>(&op))
        return addToTable(immTable, *imm);
    if(auto *reg = std::get_if<RegOp>(&op))
        return addToTable(regTable, *reg);
    if(auto *indirect = std::get_if<IndirectOp>(&op))
        return addToTable(indirectTable, *indirect);
    assert("Operand has invalid value");
    return 0;
}
