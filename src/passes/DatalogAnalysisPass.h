//===- DatalogAnalysisPass.h =-----------------------------------*- C++ -*-===//
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
#ifndef _DATALOG_ANALYSIS_PASS_H_
#define _DATALOG_ANALYSIS_PASS_H_

#include <boost/filesystem.hpp>
#include <chrono>
#include <gtirb/gtirb.hpp>
#include <list>
#include <optional>
#include <string>

#include "../gtirb-decoder/DatalogIO.h"
#include "AnalysisPass.h"

enum DatalogExecutionMode
{
    SYNTHESIZED,
    INTERPRETED,
};

class DatalogAnalysisPass : public AnalysisPass
{
public:
    virtual AnalysisPassResult analyze(const gtirb::Module& Module) override;
    virtual void clear() override;

    void configureSouffleInterpreter(const std::string& Path, const std::string& LibDir_)
    {
        ExecutionMode = DatalogExecutionMode::INTERPRETED;
        InterpreterPath = (fs::path(Path) / getSourceFilename()).string();
        LibDir = LibDir_;
    }
    void setProfileDir(const std::string& Path)
    {
        ProfilePath = (fs::path(Path) / (getNameSlug() + ".prof")).string();
    }
    void setThreadCount(int J)
    {
        ThreadCount = J;
    }
    void enableSouffleOutputs(bool Enable = true)
    {
        WriteSouffleOutputs = Enable;
    }
    void readHints(const std::string& Filename);

    souffle::SouffleProgram& getProgram()
    {
        return *Program;
    };

    virtual bool hasLoad(void) override
    {
        return true;
    }

protected:
    virtual void analyzeImpl(AnalysisPassResult& Result, const gtirb::Module& Module) override;
    virtual void transformImpl(AnalysisPassResult& Result, gtirb::Context& Context,
                               gtirb::Module& Module) override;

    /**
    Get the filename of the Datalog source file.
    */
    virtual std::string getSourceFilename() const = 0;

    std::string InterpreterPath;
    std::string LibDir;
    std::string ProfilePath;
    DatalogExecutionMode ExecutionMode = DatalogExecutionMode::SYNTHESIZED;
    int ThreadCount = 1;

    std::unique_ptr<souffle::SouffleProgram> Program;
    bool WriteSouffleOutputs = false;
};

#endif /* _DATALOG_ANALYSIS_PASS_H_ */
