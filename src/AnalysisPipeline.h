//===- AnalysisPipeline.h =---------------------------------------*- C++ -*-===//
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
#ifndef _ANALYSIS_PIPELINE_H_
#define _ANALYSIS_PIPELINE_H_
#include "Hints.h"
#include "passes/AnalysisPass.h"

enum AnalysisPassPhase
{
    LOAD = 1,
    ANALYZE,
    TRANSFORM
};

/**
An AnalysisPipelineListener is notified regarding AnalysisPipeline events.

It is intended for implementation of user interfaces.
*/
class AnalysisPipelineListener
{
public:
    virtual void notifyPassBegin(const AnalysisPass& Name) = 0;
    virtual void notifyPassEnd(const AnalysisPass& Pass) = 0;
    virtual void notifyPassPhase(AnalysisPassPhase Phase, bool HasPhase = true) = 0;
    virtual void notifyPassResult(AnalysisPassPhase Phase, const AnalysisPassResult& Result) = 0;
};

class AnalysisPipeline
{
public:
    void addListener(std::shared_ptr<AnalysisPipelineListener> Listener)
    {
        Listeners.push_back(Listener);
    }

    template <typename T, typename... A>
    void push(A&&... Args)
    {
        Passes.push_back(std::make_unique<T>(std::forward<A>(Args)...));
    }

    void configureDebugDir(const std::string& DebugDirRoot, bool MultiModule);
    void setDatalogThreadCount(unsigned int Count);
    void setDatalogProfileDir(const std::string& ProfileDir);
    void enableSouffleOutputs();
    void configureSouffleInterpreter(const std::string& InterpreterDir,
                                     const std::string& LibraryDir);
    void loadHints(const std::string& Path);

    void run(gtirb::Context& Context, gtirb::Module& Module);

private:
    std::set<std::string> getPassSlugs();
    void notifyPassBegin(const AnalysisPass& Name);
    void notifyPassEnd(const AnalysisPass& Pass);
    void notifyPassPhase(AnalysisPassPhase Phase, bool HasPhase = true);
    void notifyPassResult(AnalysisPassPhase Phase, const AnalysisPassResult& Result);

    std::list<std::shared_ptr<AnalysisPipelineListener>> Listeners;
    std::list<std::unique_ptr<AnalysisPass>> Passes;
    HintsLoader DatalogHints;
};
#endif /* _ANALYSIS_PIPELINE_H_ */
