//===- DatalogProgram.h -----------------------------------------*- C++ -*-===//
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

#include <gtirb/gtirb.hpp>

#include "DatalogLoader.h"
#include "DatalogProgram.h"

namespace souffle
{
    souffle::tuple &operator<<(souffle::tuple &T, const gtirb::Addr &A);

    // souffle::tuple &operator<<(souffle::tuple &T, const InstructionDecoder::Instruction &I);

    template <typename U>
    souffle::tuple &operator<<(souffle::tuple &T, const DataDecoder::Data<U> &Data)
    {
        T << Data.Addr << Data.Item;
        return T;
    }
} // namespace souffle

template <typename T>
void DatalogProgram::insert(const std::string &Name, const T &Data)
{
    if(auto *Relation = Program->getRelation(Name))
    {
        for(const auto Element : Data)
        {
            souffle::tuple Row(Relation);
            Row << Element;
            Relation->insert(Row);
        }
    }
}

// FIXME: remove specialization when we use this
template <>
void DatalogProgram::insert(const std::string &Name, const std::vector<std::string> &Data)
{
    if(auto *Relation = Program->getRelation(Name))
    {
        for(const auto Element : Data)
        {
            souffle::tuple Row(Relation);
            Row << Element;
            Relation->insert(Row);
        }
    }
}

template <>
void DatalogProgram::insert(const std::string &Name, const std::vector<gtirb::Addr> &Data)
{
    if(auto *Relation = Program->getRelation(Name))
    {
        for(const auto Element : Data)
        {
            souffle::tuple Row(Relation);
            Row << Element;
            Relation->insert(Row);
        }
    }
}

template <>
void DatalogProgram::insert(const std::string &Name,
                            const std::vector<DataDecoder::Data<gtirb::Addr>> &Data)
{
    if(auto *Relation = Program->getRelation(Name))
    {
        for(const auto Element : Data)
        {
            souffle::tuple Row(Relation);
            Row << Element;
            Relation->insert(Row);
        }
    }
}

template <>
void DatalogProgram::insert(const std::string &Name,
                            const std::vector<DataDecoder::Data<uint8_t>> &Data)
{
    if(auto *Relation = Program->getRelation(Name))
    {
        for(const auto Element : Data)
        {
            souffle::tuple Row(Relation);
            Row << Element;
            Relation->insert(Row);
        }
    }
}
