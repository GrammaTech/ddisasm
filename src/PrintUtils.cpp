//===- PrintUtils.cpp -------------------------------------------*- C++ -*-===//
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
#include "PrintUtils.h"

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

/**
Prints pass results

returns whether warnings were emitted
*/
bool printPassResults(const AnalysisPassResult &Result)
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
    return !Result.Warnings.empty();
}
