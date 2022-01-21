//===- Interpreter.cpp ------------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2021 GrammaTech, Inc.
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
#include "Interpreter.h"

#include <souffle/CompiledSouffle.h>

#include <boost/filesystem.hpp>
#include <boost/process/search_path.hpp>
#include <boost/process/system.hpp>

std::string getInterpreterArch(const gtirb::Module &Module)
{
    switch(Module.getISA())
    {
        case gtirb::ISA::IA32:
            return "-MARCH_IA32";
        case gtirb::ISA::X64:
            return "-MARCH_AMD64";
        case gtirb::ISA::ARM:
            return "-MARCH_ARM32";
        case gtirb::ISA::ARM64:
            return "-MARCH_ARM64";
        case gtirb::ISA::MIPS32:
            return "-MARCH_MIPS32";
        default:
            assert(!"Unsupported GTIRB ISA");
    }
    return "";
}

void loadAll(souffle::SouffleProgram *Program, const std::string &Directory)
{
    // Load output relations into synthesized SouffleProgram.
    for(souffle::Relation *Relation : Program->getOutputRelations())
    {
        const std::string Path = Directory + "/" + Relation->getName() + ".csv";
        std::ifstream CSV(Path);
        if(!CSV)
        {
            std::cerr << "Error: missing output relation `" << Path << "'\n";
            continue;
        }
        std::string Line;
        while(std::getline(CSV, Line))
        {
            std::stringstream Row(Line);
            souffle::tuple T(Relation);

            std::string Field;

            for(size_t I = 0; I < Relation->getArity(); I++)
            {
                if(Relation->getArity() == 1)
                {
                    Field = Line;
                }
                else if(!std::getline(Row, Field, '\t'))
                {
                    assert(!"CSV file has less fields than expected");
                }
                switch(Relation->getAttrType(I)[0])
                {
                    case 's':
                    {
                        T << Field;
                        break;
                    }
                    case 'i':
                    {
                        int64_t Number = std::stoll(Field);
                        T << Number;
                        break;
                    }
                    case 'u':
                    {
                        uint64_t Number = std::stoull(Field);
                        T << Number;
                        break;
                    }
                    case 'f':
                    {
                        T << std::stod(Field);
                        break;
                    }
                    default:
                        assert(!"Invalid type attribute");
                }
            }

            Relation->insert(T);
        }
    }
}

void runInterpreter(gtirb::Module &Module, souffle::SouffleProgram *Program,
                    const std::string &DatalogFile, const std::string &Directory, uint8_t Threads)
{
    // Search PATH for `souffle' binary.
    boost::filesystem::path SouffleBinary = boost::process::search_path("souffle");
    if(SouffleBinary.empty())
    {
        std::cerr << "Error: could not find `souffle' on the PATH.\n";
        std::exit(EXIT_FAILURE);
    }

    // Build `souffle' command-line arguments.
    std::string Arch = getInterpreterArch(Module);
    std::vector<std::string> Args = {Arch,
                                     "--fact-dir",
                                     Directory,
                                     "--output-dir",
                                     Directory,
                                     "--jobs",
                                     std::to_string(Threads),
                                     DatalogFile};

    // Execute the `souffle' interpreter.
    int Code = boost::process::system(SouffleBinary, Args);
    if(Code)
    {
        std::cerr << "Error: `souffle' return non-zero exit code: " << Code << "\n";
        std::exit(EXIT_FAILURE);
    }

    // Load the output relations back into the synthesized program context.
    loadAll(Program, Directory);
}
