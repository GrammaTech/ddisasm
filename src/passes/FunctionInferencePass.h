//===- FunctionInferencePass.h ----------------------------------*- C++ -*-===//
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
#ifndef FUNCTION_INFERENCE_PASS_H_
#define FUNCTION_INFERENCE_PASS_H_

#include <souffle/SouffleInterface.h>

#include <gtirb/gtirb.hpp>
#include <optional>

// Refine function boundaries.
class FunctionInferencePass
{
public:
    void setDebugDir(std::string Path)
    {
        DebugDir = Path;
    };

    void computeFunctions(gtirb::Context& C, gtirb::Module& M, unsigned int NThreads);

private:
    std::optional<std::string> DebugDir;
    void updateFunctions(souffle::SouffleProgram* P, gtirb::Module& M);
};
#endif // FUNCTION_INFERENCE_PASS_H_
