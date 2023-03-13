//===- AnalysisPass.cpp =----------------------------------------*- C++ -*-===//
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
#include "AnalysisPass.h"

std::string AnalysisPass::getNameSlug() const
{
    std::string Name = getName();
    std::replace(Name.begin(), Name.end(), ' ', '-');
    return Name;
}

AnalysisPassResult AnalysisPass::load(const gtirb::Context& Context, const gtirb::Module& Module,
                                      AnalysisPass* PreviousPass)
{
    AnalysisPassResult Result;
    auto StartTime = std::chrono::high_resolution_clock::now();
    loadImpl(Result, Context, Module, PreviousPass);
    Result.RunTime = std::chrono::high_resolution_clock::now() - StartTime;
    return Result;
}

AnalysisPassResult AnalysisPass::analyze(const gtirb::Module& Module)
{
    AnalysisPassResult Result;
    auto StartTime = std::chrono::high_resolution_clock::now();
    analyzeImpl(Result, Module);
    Result.RunTime = std::chrono::high_resolution_clock::now() - StartTime;
    return Result;
}

AnalysisPassResult AnalysisPass::transform(gtirb::Context& Context, gtirb::Module& Module)
{
    AnalysisPassResult Result;
    auto StartTime = std::chrono::high_resolution_clock::now();
    transformImpl(Result, Context, Module);
    Result.RunTime = std::chrono::high_resolution_clock::now() - StartTime;
    return Result;
}

void AnalysisPass::clear()
{
}
