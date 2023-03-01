//===- Hints.h --------------------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2023 GrammaTech, Inc.
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
#ifndef _HINTS_H_
#define _HINTS_H_
#include <list>
#include <map>
#include <set>
#include <string>

#include "gtirb-decoder/DatalogIO.h"

class HintsLoader
{
public:
    /**
    Load hints file from disk.
    */
    void read(const std::string& FileName, const std::set<std::string>& Namespaces);

    /**
    Inserts loaded hints into a souffle program

    Has no effect if read() was never called.
    */
    void insert(souffle::SouffleProgram& Program, const std::string& Namespace);

private:
    // map of (namespace -> map(relation name -> list(pair(lineno, tuple text))))
    std::unordered_map<std::string,
                       std::unordered_map<std::string, std::list<std::pair<uint32_t, std::string>>>>
        HintsTable;
};

#endif /* _HINTS_H_ */
