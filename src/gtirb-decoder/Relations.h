//===- Relations.h ----------------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2020 GrammaTech, Inc.
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
#ifndef SRC_GTIRB_DECODER_RELATIONS_H_
#define SRC_GTIRB_DECODER_RELATIONS_H_

#include <map>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <souffle/CompiledSouffle.h>
#include <souffle/SouffleInterface.h>
#include <gtirb/gtirb.hpp>

namespace relations
{
    template <class T>
    struct Data
    {
        gtirb::Addr Addr;
        T Item;
    };

    struct Instruction
    {
        uint64_t Address;
        uint64_t Size;
        std::string Prefix;
        std::string Name;
        std::vector<uint64_t> OpCodes;
        uint8_t ImmediateOffset;
        uint8_t DisplacementOffset;
    };

    using ImmOp = int64_t;
    using RegOp = std::string;
    struct IndirectOp
    {
        std::string Reg1;
        std::string Reg2;
        std::string Reg3;
        int64_t Mult;
        int64_t Disp;
        int Size;

        constexpr bool operator<(const IndirectOp& Op) const noexcept
        {
            return std::tie(Reg1, Reg2, Reg3, Mult, Disp, Size)
                   < std::tie(Op.Reg1, Op.Reg2, Op.Reg3, Op.Mult, Op.Disp, Op.Size);
        };
    };

    using Operand = std::variant<ImmOp, RegOp, IndirectOp>;

    struct OperandTable
    {
        template <typename T>
        uint64_t add(std::map<T, uint64_t>& OpTable, T& Op)
        {
            auto [Iter, Inserted] = OpTable.try_emplace(std::forward<T>(Op), Index);
            if(Inserted)
            {
                Index++;
            }
            return Iter->second;
        }

        uint64_t operator()(ImmOp& Op)
        {
            return add(ImmTable, Op);
        }

        uint64_t operator()(RegOp& Op)
        {
            return add(RegTable, Op);
        }

        uint64_t operator()(IndirectOp& Op)
        {
            return add(IndirectTable, Op);
        }

        // We reserve 0 for empty operators.
        uint64_t Index = 1;

        std::map<ImmOp, uint64_t> ImmTable;
        std::map<RegOp, uint64_t> RegTable;
        std::map<IndirectOp, uint64_t> IndirectTable;
    };

    struct Symbol
    {
        gtirb::Addr Addr;
        uint64_t Size;
        std::string Type;
        std::string Binding;
        std::string Visibility;
        uint64_t SectionIndex;
        std::string Name;
    };

    struct Section
    {
        std::string Name;
        uint64_t Size;
        gtirb::Addr Address;
        uint64_t Type;
        uint64_t Flags;
    };

} // namespace relations

namespace souffle
{
    souffle::tuple& operator<<(souffle::tuple& T, const gtirb::Addr& A);

    souffle::tuple& operator<<(souffle::tuple& T, const relations::Symbol& S);

    souffle::tuple& operator<<(souffle::tuple& T, const relations::Section& S);

    souffle::tuple& operator<<(souffle::tuple& T, const relations::Instruction& I);

    souffle::tuple& operator<<(souffle::tuple& T, const relations::IndirectOp& I);

    template <typename Item>
    souffle::tuple& operator<<(souffle::tuple& T, const relations::Data<Item>& Data)
    {
        T << Data.Addr << Data.Item;
        return T;
    }

    template <class U>
    souffle::tuple& operator<<(souffle::tuple& T, const std::pair<U, uint64_t>& Pair)
    {
        auto& [Element, Id] = Pair;
        T << Id << Element;
        return T;
    }
} // namespace souffle

#endif // SRC_GTIRB_DECODER_RELATIONS_H_
