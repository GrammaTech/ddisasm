//===- DatalogUtils.h ---------------------------------------------*- C++ -*-===//
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

#ifndef DATALOG_UTILS_H_
#define DATALOG_UTILS_H_

#include <capstone/capstone.h>
#include <souffle/CompiledSouffle.h>
#include <souffle/SouffleInterface.h>
#include <gtirb/gtirb.hpp>
#include "DlOperandTable.h"

void writeFacts(souffle::SouffleProgram *prog, const std::string &directory);

struct DlInstruction
{
    uint64_t address;
    long size;
    std::string prefix;
    std::string name;
    std::vector<uint64_t> op_codes;
    uint8_t immediateOffset;
    uint8_t displacementOffset;
};

namespace souffle
{
    souffle::tuple &operator<<(souffle::tuple &t, const gtirb::Addr &a);
    souffle::tuple &operator<<(souffle::tuple &t, const DlInstruction &inst);
} // namespace souffle

class GtirbToDatalog
{
private:
    std::shared_ptr<souffle::SouffleProgram> Prog;

public:
    GtirbToDatalog(std::shared_ptr<souffle::SouffleProgram> P) : Prog(P)
    {
    }

    static DlInstruction transformInstruction(const csh &CsHandle, DlOperandTable &OpDict,
                                              const cs_insn &insn);

    template <typename T>
    static void addToRelation(souffle::SouffleProgram *prog, const std::string &name, const T &data)
    {
        if(auto *rel = prog->getRelation(name))
        {
            for(const auto elt : data)
            {
                souffle::tuple t(rel);
                t << elt;
                rel->insert(t);
            }
        }
    }

    void populateBlocks(const gtirb::Module &M);
    void populateInstructions(const gtirb::Module &M, int InstructionLimit = 0);
    void populateCfgEdges(const gtirb::Module &M);
    void populateSccs(gtirb::Module &M);
    void populateSymbolicExpressions(const gtirb::Module &M);
    void populateFdeEntries(const gtirb::Context &Ctx, gtirb::Module &M);
    void populateFunctionEntries(const gtirb::Context &Ctx, gtirb::Module &M);
    void populatePadding(const gtirb::Context &Ctx, gtirb::Module &M);
};

#endif
