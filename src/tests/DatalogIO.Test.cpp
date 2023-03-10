//===- DatalogIO.Test.cpp ----------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2022 GrammaTech, Inc.
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
#include <gtest/gtest.h>
#include <souffle/CompiledSouffle.h>
#include <souffle/SouffleInterface.h>

#include "../gtirb-decoder/DatalogIO.h"

TEST(DatalogIOTest, TestInsertTuple)
{
    auto Program = std::unique_ptr<souffle::SouffleProgram>(
        souffle::ProgramFactory::newInstance("souffle_disasm_arm64"));

    souffle::Relation *Relation = Program->getRelation("stack_def_use.def_used");

    // Currently, this is the only relation that uses record types.
    std::string TupleText("0x778\t[SP, 16]\t0x7ac\t[SP, 16]\t1\n");
    DatalogIO::insertTuple(TupleText, *Program, Relation);

    // Read the tuple back.
    auto TupleIt = Relation->begin();

    // We should have a valid tuple iterator.
    ASSERT_NE(TupleIt, Relation->end());

    // Tuple should have four attributes.
    ASSERT_EQ((*TupleIt).size(), 5);

    ASSERT_EQ(souffle::ramBitCast<souffle::RamUnsigned>((*TupleIt)[0]), 0x778);

    // Verify records
    const souffle::RamDomain *Record = Program->getRecordTable().unpack((*TupleIt)[1], 2);
    ASSERT_EQ(Program->getSymbolTable().decode(Record[0]), "SP");
    ASSERT_EQ(Record[1], 16);

    Record = Program->getRecordTable().unpack((*TupleIt)[3], 2);
    ASSERT_EQ(Program->getSymbolTable().decode(Record[0]), "SP");
    ASSERT_EQ(Record[1], 16);

    ASSERT_EQ(souffle::ramBitCast<souffle::RamUnsigned>((*TupleIt)[2]), 0x7ac);
    ASSERT_EQ(souffle::ramBitCast<souffle::RamUnsigned>((*TupleIt)[4]), 1);

    TupleIt++;

    // Ensure there is only one tuple.
    ASSERT_EQ(TupleIt, Relation->end());

    // Serialize the tuple
    std::stringstream OutputStream("");
    DatalogIO::writeRelation(OutputStream, *Program, Relation);

    // Confirm that the output matches the input.
    ASSERT_EQ(TupleText, OutputStream.str());
}
