//===- DatalogIO.h -----------------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2020-2023 GrammaTech, Inc.
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
#ifndef _DATALOG_IO_H_
#define _DATALOG_IO_H_

#include <souffle/CompiledSouffle.h>
#include <souffle/SouffleInterface.h>

#include <memory>
#include <sstream>
#include <string>
#include <tuple>

namespace DatalogIO
{
    void serializeRecord(std::ostream& Stream, souffle::SouffleProgram& Program,
                         const std::string& AttrType, souffle::RamDomain RecordId);
    void serializeAttribute(std::ostream& Stream, souffle::SouffleProgram& Program,
                            const std::string& AttrType, souffle::RamDomain Data);
    void serializeType(std::ostream& Stream, souffle::Relation* Relation);

    souffle::RamDomain insertRecord(souffle::SouffleProgram& Program,
                                    const std::string& RecordText);

    bool insertTuple(const std::string& Text, souffle::SouffleProgram& Program,
                     souffle::Relation* Relation);

    void writeRelation(std::ostream& Stream, souffle::SouffleProgram& Program,
                       const souffle::Relation* Relation);

    void writeRelations(const std::string& Directory, const std::string& FileExtension,
                        souffle::SouffleProgram& Program,
                        const std::vector<souffle::Relation*>& Relations);

    void writeFacts(const std::string& Direcory, souffle::SouffleProgram& Program);
    void writeRelations(const std::string& Directory, souffle::SouffleProgram& Program);

    void readRelations(souffle::SouffleProgram& Program, const std::string& Directory);

    void setProfilePath(const std::string& ProfilePath);
    std::string clearProfileDB();
}; // namespace DatalogIO

#endif // _DATALOG_IO_H_
