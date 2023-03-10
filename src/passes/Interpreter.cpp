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

#include <boost/dll.hpp>
#include <boost/filesystem.hpp>
#include <boost/process/args.hpp>
#include <boost/process/env.hpp>
#include <boost/process/environment.hpp>
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

void runInterpreter(const gtirb::IR &IR, const gtirb::Module &Module,
                    souffle::SouffleProgram &Program, const std::string &DatalogFile,
                    const std::string &Directory, const std::string &LibDirectory,
                    const std::string &ProfilePath, uint8_t Threads)
{
    // Dump the current GTIRB into the debug directory for use by Functors.
    std::ofstream out(Directory + "/binary.gtirb", std::ios::out | std::ios::binary);
    IR.save(out);
    out.close();

    // Put the debug directory in an env variable for Functors.
    boost::process::environment Env = boost::this_process::environment();
    Env["DDISASM_DEBUG_DIR"] = Directory;
    Env["DDISASM_GTIRB_MODULE_NAME"] = Module.getName();

    // Search PATH for `souffle' binary.
    boost::filesystem::path SouffleBinary = boost::process::search_path("souffle");
    if(SouffleBinary.empty())
    {
        std::cerr << "Error: could not find `souffle' on the PATH.\n";
        std::exit(EXIT_FAILURE);
    }

    // Locate libfunctors.so
    // If LibDirectory is provided, only check there. Otherwise, search:
    // (directory of running ddisasm)/../lib/
    // ./ (Current directory)
    std::string FinalLibDirectory;
    if(!LibDirectory.empty())
    {
        if(!boost::filesystem::exists(boost::filesystem::path(LibDirectory) / "libfunctors.so"))
        {
            std::cerr << "Error: 'libfunctors.so' not in " << LibDirectory << ".\n";
            std::exit(EXIT_FAILURE);
        }
        FinalLibDirectory = LibDirectory;
    }
    else
    {
        const std::vector<boost::filesystem::path> LibSearchPaths = {
            boost::dll::program_location().parent_path() / "../lib",
            ".",
        };

        for(auto It = LibSearchPaths.begin(); It < LibSearchPaths.end(); It++)
        {
            if(boost::filesystem::exists(*It / "libfunctors.so"))
            {
                FinalLibDirectory = It->string();
                break;
            }
        }

        if(FinalLibDirectory.empty())
        {
            std::cerr << "Error: could not find 'libfunctors.so'.\n";
            std::exit(EXIT_FAILURE);
        }
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
                                     "--library-dir",
                                     FinalLibDirectory,
                                     DatalogFile};

    if(!ProfilePath.empty())
    {
        Args.insert(Args.end(), {"--compile", "--profile", ProfilePath});
    }

    // Execute the `souffle' interpreter.
    int Code = boost::process::system(SouffleBinary, Args, Env);
    if(Code)
    {
        std::cerr << "Error: `souffle' return non-zero exit code: " << Code << "\n";
        std::exit(EXIT_FAILURE);
    }

    // Load the output relations back into the synthesized program context.
    DatalogIO::readRelations(Program, Directory);
}
