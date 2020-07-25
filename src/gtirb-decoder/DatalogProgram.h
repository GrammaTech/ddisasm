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
#ifndef SRC_DATALOG_PROGRAM_H_
#define SRC_DATALOG_PROGRAM_H_

#include <memory>

#include <souffle/SouffleInterface.h>

class DatalogProgram
{
public:
    DatalogProgram(std::shared_ptr<souffle::SouffleProgram> P) : Program{P} {};
    ~DatalogProgram() = default;

    template <typename T>
    void insert(const std::string& Name, const T& Data);

private:
    std::shared_ptr<souffle::SouffleProgram> Program;
};

#endif /* SRC_DATALOG_PROGRAM_H_ */
