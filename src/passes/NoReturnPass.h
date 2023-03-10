//===- NoReturnPass.h -------------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2019-2023 GrammaTech, Inc.
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
#ifndef NO_RETURN_PASS_H_
#define NO_RETURN_PASS_H_

#include <gtirb/gtirb.hpp>

#include "DatalogAnalysisPass.h"

/**
Refine the CFG by removing fallthrough edges whenever there is a call to a block that never
returns.
*/
class NoReturnPass : public DatalogAnalysisPass
{
    virtual std::string getName() const override
    {
        return "no return analysis";
    }

    virtual std::string getSourceFilename() const override
    {
        return "src/passes/datalog/no_return_analysis.dl";
    }

    virtual bool hasLoad(void) override
    {
        return true;
    }
    virtual bool hasTransform(void) override
    {
        return true;
    }

protected:
    void loadImpl(AnalysisPassResult& Result, const gtirb::Context& Context,
                  const gtirb::Module& Module, AnalysisPass* PreviousPass = nullptr) override;
    void transformImpl(AnalysisPassResult& Result, gtirb::Context& Context,
                       gtirb::Module& Module) override;
};
#endif // NO_RETURN_PASS_H_
