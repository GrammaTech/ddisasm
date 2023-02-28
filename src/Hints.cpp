//===- Hints.cpp ------------------------------------------------*- C++ -*-===//
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
#include "Hints.h"

#include <iostream>

void HintsLoader::read(const std::string &FileName, const std::set<std::string> &Namespaces)
{
    std::ifstream Stream(FileName);
    if(!Stream)
    {
        std::cerr << "ERROR: could not find hints file `" << FileName << "'\n";
        return;
    }

    std::string Line;
    int LineNumber = 0;
    while(std::getline(Stream, Line))
    {
        ++LineNumber;
        std::stringstream Row(Line);
        std::string Namespace;
        std::string RelationName;
        if(!std::getline(Row, Namespace, '.') || !std::getline(Row, RelationName, '\t'))
        {
            std::cerr << "WARNING: ignoring hint in line " << LineNumber << ": '" << Line << "'\n";
            continue;
        }

        if(!Namespaces.count(Namespace))
        {
            std::cerr << "WARNING: ignoring hint in line " << LineNumber << ": unknown pass "
                      << Namespace << std::endl;
            continue;
        }

        std::string Remainder;
        std::getline(Row, Remainder);
        HintsTable[Namespace][RelationName].emplace_back(LineNumber, Remainder);
    }
}

void HintsLoader::insert(souffle::SouffleProgram &Program, const std::string &Namespace)
{
    for(auto &[RelationName, Hints] : HintsTable[Namespace])
    {
        for(auto &[LineNumber, Hint] : Hints)
        {
            souffle::Relation *Relation = Program.getRelation(RelationName);
            if(!Relation)
            {
                std::cerr << "WARNING: ignoring hint in line " << LineNumber
                          << ": unknown relation " << RelationName << std::endl;
                continue;
            }

            if(!DatalogIO::insertTuple(Hint, Program, Relation))
            {
                std::cerr << "WARNING: ignoring hint in line " << LineNumber << ": bad format"
                          << std::endl;
            }
        }
    }
}
