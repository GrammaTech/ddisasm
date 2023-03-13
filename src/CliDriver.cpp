//===- CliDriver.cpp ---------------------------------------------*- C++ -*-===//
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
#include "CliDriver.h"

// Define CLI output field widths
constexpr size_t IndentWidth = 4;
constexpr size_t TimeWidth = 8;
constexpr size_t PassNameWidth = 18;
constexpr size_t PassStepWidth = 12;

void printElapsedTime(std::chrono::duration<double> Elapsed)
{
    auto Hours = std::chrono::duration_cast<std::chrono::hours>(Elapsed).count();
    auto Minutes = std::chrono::duration_cast<std::chrono::minutes>(Elapsed).count();
    auto Secs = std::chrono::duration_cast<std::chrono::seconds>(Elapsed).count();
    auto Millis = std::chrono::duration_cast<std::chrono::milliseconds>(Elapsed).count();

    std::stringstream FmttedDuration;

    if(Hours > 0)
    {
        FmttedDuration << Hours << "h" << (Minutes % 60) << "m";
    }
    else if(Minutes > 0)
    {
        FmttedDuration << Minutes << "m" << (Secs % 60) << "s";
    }
    else if(Secs > 0)
    {
        FmttedDuration << Secs << "s";
    }
    else
    {
        FmttedDuration << Millis << "ms";
    }

    // set width to TimeWidth-2; it includes the size of the brackets
    std::cerr << "[" << std::right << std::setw(TimeWidth - 2) << FmttedDuration.str() << "]";
}

void printElapsedTimeSince(std::chrono::time_point<std::chrono::high_resolution_clock> Start)
{
    auto End = std::chrono::high_resolution_clock::now();
    printElapsedTime(End - Start);
}

void DDisasmPipelineListener::notifyPassBegin(const AnalysisPass &Pass)
{
    std::cerr << std::setw(IndentWidth) << "" << std::left << std::setw(PassNameWidth)
              << Pass.getName() << std::flush;
}

void DDisasmPipelineListener::notifyPassEnd([[maybe_unused]] const AnalysisPass &Pass)
{
    std::cerr << "\n";
}

void DDisasmPipelineListener::notifyPassPhase(AnalysisPassPhase Phase, bool HasPhase)
{
    std::string Name;
    switch(Phase)
    {
        case AnalysisPassPhase::LOAD:
            Name = "load";
            break;
        case AnalysisPassPhase::ANALYZE:
            Name = "compute";
            break;
        case AnalysisPassPhase::TRANSFORM:
            Name = "transform";
            break;
    }
    if(HasPhase)
    {
        std::cerr << std::right << std::setw(PassStepWidth) << (Name + " ");
    }
    else
    {
        std::cerr << std::setw(PassStepWidth + TimeWidth) << "";
    }
    std::cerr << std::flush;
}

void DDisasmPipelineListener::notifyPassResult(AnalysisPassPhase Phase,
                                               const AnalysisPassResult &Result)
{
    printElapsedTime(Result.RunTime);
    if(!Result.Warnings.empty() || !Result.Errors.empty())
    {
        std::cerr << "\n";
    }
    for(const std::string &Warning : Result.Warnings)
    {
        std::cerr << "WARNING: " << Warning << "\n";
    }
    for(const std::string &Error : Result.Errors)
    {
        std::cerr << "ERROR: " << Error << "\n" << std::flush;
    }
    if(!Result.Errors.empty())
    {
        std::exit(EXIT_FAILURE);
    }
    if(!Result.Warnings.empty())
    {
        size_t PaddingMult;
        switch(Phase)
        {
            case AnalysisPassPhase::LOAD:
                PaddingMult = 1;
                break;
            case AnalysisPassPhase::ANALYZE:
                PaddingMult = 2;
                break;
            case AnalysisPassPhase::TRANSFORM:
                PaddingMult = 2;
                break;
        }

        // Re-indent after emitting warnings
        std::cerr << std::setw(IndentWidth + PassNameWidth
                               + PaddingMult * (PassStepWidth + TimeWidth))
                  << "";
    }
}
