//===- SccPass.h ------------------------------------------------*- C++ -*-===//
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
#ifndef SCC_PASS_H_
#define SCC_PASS_H_

#include <gtirb/gtirb.hpp>

#include "AnalysisPass.h"

using SccMap = std::map<gtirb::UUID, int64_t>;

/**
Compute strongly connected components and store them in a AuxData table SccMap called "SCCs"
*/
class SccPass : public AnalysisPass
{
public:
    virtual std::string getName() const override
    {
        return "SCC analysis";
    }

    virtual bool hasTransform(void) override
    {
        return true;
    }

    virtual void clear() override;

protected:
    virtual void loadImpl(AnalysisPassResult& Result, const gtirb::Context& Context,
                          const gtirb::Module& Module,
                          AnalysisPass* PreviousPass = nullptr) override;
    virtual void analyzeImpl(AnalysisPassResult& Result, const gtirb::Module& Module) override;
    virtual void transformImpl(AnalysisPassResult& Result, gtirb::Context& Context,
                               gtirb::Module& Module) override;

private:
    SccMap Sccs;
};

#endif // SCC_PASS_H_
