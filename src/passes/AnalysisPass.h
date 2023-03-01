//===- AnalysisPass.h =------------------------------------------*- C++ -*-===//
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
#ifndef _ANALYSIS_PASS_H_
#define _ANALYSIS_PASS_H_

#include <boost/filesystem.hpp>
#include <chrono>
#include <gtirb/gtirb.hpp>
#include <list>
#include <string>

namespace fs = boost::filesystem;

struct AnalysisPassResult
{
    std::list<std::string> Warnings;
    std::list<std::string> Errors;
    std::chrono::duration<double> RunTime;
};

/**
An analysis pass represents a unit of analysis applied to a gtirb module.

Analysis passes may be implemented in Datalog or C++.
*/
class AnalysisPass
{
public:
    virtual ~AnalysisPass() = default;

    virtual std::string getName() const = 0;

    /**
    Derive a name with no spaces.
    */
    std::string getNameSlug() const;

    virtual bool hasLoad(void)
    {
        return false;
    }
    virtual bool hasTransform(void)
    {
        return false;
    }

    /**
    Load data from the GTIRB.
    */
    virtual AnalysisPassResult load(const gtirb::Context& Context, const gtirb::Module& Module,
                                    AnalysisPass* PreviousPass = nullptr);

    /**
    Perform analysis.
    */
    virtual AnalysisPassResult analyze(const gtirb::Module& Module);

    /**
    Apply changes to the GTIRB.
    */
    virtual AnalysisPassResult transform(gtirb::Context& Context, gtirb::Module& Module);

    void configureDebugDir(const std::string& DebugDirRoot_, bool MultiModule_)
    {
        DebugDirRoot = DebugDirRoot_;
        MultiModule = MultiModule_;
    }

    /**
    Prepare for running the pass on an additional Module with the same settings.
    */
    virtual void clear();

protected:
    virtual void loadImpl(AnalysisPassResult& Result, const gtirb::Context& Context,
                          const gtirb::Module& Module, AnalysisPass* PreviousPass = nullptr) = 0;
    virtual void analyzeImpl(AnalysisPassResult& Result, const gtirb::Module& Module) = 0;
    virtual void transformImpl(AnalysisPassResult& Result, gtirb::Context& Context,
                               gtirb::Module& Module) = 0;
    std::string DebugDirRoot;
    bool MultiModule = false;

    std::string getDebugDir(const gtirb::Module& Module)
    {
        fs::path RootPath(DebugDirRoot);

        fs::path DebugDir(MultiModule ? RootPath / Module.getName() / getNameSlug()
                                      : RootPath / getNameSlug());
        fs::create_directories(DebugDir);
        return DebugDir.string();
    }
};

#endif // _ANALYSIS_PASS_H_
