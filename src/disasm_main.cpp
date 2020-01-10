//===- disasm_main.cpp ------------------------------------------*- C++ -*-===//
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
#include <souffle/CompiledSouffle.h>
#include <souffle/SouffleInterface.h>
#include <boost/program_options.hpp>
#include <gtirb/gtirb.hpp>
#include <gtirb_pprinter/PrettyPrinter.hpp>
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include "DatalogUtils.h"
#include "DlDecoder.h"
#include "GtirbModuleDisassembler.h"
#include "GtirbZeroBuilder.h"
#include "passes/FunctionInferencePass.h"
#include "passes/NoReturnPass.h"
#include "passes/SccPass.h"

namespace po = boost::program_options;

namespace std
{
    // program_options default values need to be printable.
    std::ostream &operator<<(std::ostream &os, const std::vector<std::string> &vec)
    {
        for(auto item : vec)
        {
            os << item << ",";
        }
        return os;
    }
} // namespace std

int main(int argc, char **argv)
{
    po::options_description desc("Allowed options");
    desc.add_options()                                                  //
        ("help", "produce help message")                                //
        ("ir", po::value<std::string>(), "GTIRB output file")           //
        ("json", po::value<std::string>(), "GTIRB json output file")    //
        ("asm", po::value<std::string>(), "ASM output file")            //
        ("debug", "generate assembler file with debugging information") //
        ("debug-dir", po::value<std::string>(),                         //
         "location to write CSV files for debugging")                   //
        ("input-file", po::value<std::string>(), "file to disasemble")  //
        ("keep-functions,K", po::value<std::vector<std::string>>()->multitoken(),
         "Print the given functions even if they are skipped by default (e.g. _start)") //
        ("self-diagnose",
         "Use relocation information to emit a self diagnose of the symbolization process. This "
         "option only works if the target binary contains complete relocation information.") //
        ("skip-function-analysis,F",
         "Skip additional analyses to compute more precise function boundaries.") //
        ("threads,j", po::value<unsigned int>()->default_value(std::thread::hardware_concurrency()),
         "Number of cores to use. It is set to the number of cores in the machine by default");
    po::positional_options_description pd;
    pd.add("input-file", -1);

    po::variables_map vm;
    try
    {
        po::store(po::command_line_parser(argc, argv).options(desc).positional(pd).run(), vm);

        if(vm.count("help"))
        {
            std::cout << "Usage: " << argv[0] << " [OPTIONS...] INPUT_FILE\n"
                      << "Disassemble INPUT_FILE and output assembly code and/or gtirb.\n\n"
                      << desc << "\n";
            return 1;
        }
        po::notify(vm);
    }
    catch(std::exception &e)
    {
        std::cerr << "Error: " << e.what() << "\nTry '" << argv[0]
                  << " --help' for more information.\n";
        return 1;
    }

    if(vm.count("input-file") < 1)
    {
        std::cerr << "Error: missing input file\nTry '" << argv[0]
                  << " --help' for more information.\n";
        return 1;
    }

    std::string filename = vm["input-file"].as<std::string>();
    std::cout << "Building the initial gtirb representation" << std::endl;
    gtirb::Context context;
    gtirb::IR *ir = buildZeroIR(filename, context);
    if(!ir)
    {
        std::cerr << "There was a problem loading the binary file " << filename << "\n";
        return 1;
    }
    gtirb::Module &module = *(ir->modules().begin());
    souffle::SouffleProgram *prog;
    {
        DlDecoder decoder;
        std::cout << "Decoding the binary" << std::endl;
        prog = decoder.decode(module);
    }
    if(prog)
    {
        std::cout << "Disassembling" << std::endl;
        unsigned int NThreads = vm["threads"].as<unsigned int>();
        prog->setNumThreads(NThreads);
        try
        {
            prog->run();
        }
        catch(std::exception &e)
        {
            souffle::SignalHandler::instance()->error(e.what());
        }
        std::cout << "Populating gtirb representation" << std::endl;
        disassembleModule(context, module, prog, vm.count("self-diagnose") != 0);

        if(vm.count("skip-function-analysis") == 0)
        {
            std::cout << "Computing intra-procedural SCCs" << std::endl;
            computeSCCs(module);
            std::cout << "Computing no return analysis" << std::endl;
            NoReturnPass NoReturn;
            FunctionInferencePass FunctionInference;
            if(vm.count("debug-dir") != 0)
            {
                NoReturn.setDebugDir(vm["debug-dir"].as<std::string>() + "/");
                FunctionInference.setDebugDir(vm["debug-dir"].as<std::string>() + "/");
            }
            NoReturn.computeNoReturn(module, NThreads);
            std::cout << "Detecting additional functions" << std::endl;
            FunctionInference.computeFunctions(context, module, NThreads);
        }
        // Output GTIRB
        if(vm.count("ir") != 0)
        {
            std::ofstream out(vm["ir"].as<std::string>(), std::ios::out | std::ios::binary);
            ir->save(out);
        }
        // Output json GTIRB
        if(vm.count("json") != 0)
        {
            std::ofstream out(vm["json"].as<std::string>());
            ir->saveJSON(out);
        }
        // Pretty-print
        gtirb_pprint::PrettyPrinter pprinter;
        pprinter.setDebug(vm.count("debug"));
        if(vm.count("keep-functions") != 0)
        {
            for(auto keep : vm["keep-functions"].as<std::vector<std::string>>())
            {
                pprinter.keepFunction(keep);
            }
        }
        if(vm.count("asm") != 0)
        {
            std::cout << "Printing assembler" << std::endl;
            std::ofstream out(vm["asm"].as<std::string>());
            pprinter.print(out, context, module);
        }
        else if(vm.count("ir") == 0)
        {
            std::cout << "Printing assembler" << std::endl;
            pprinter.print(std::cout, context, module);
        }

        if(vm.count("debug-dir") != 0)
        {
            std::cout << "Writing facts to debug dir " << vm["debug-dir"].as<std::string>()
                      << std::endl;
            auto dir = vm["debug-dir"].as<std::string>() + "/";
            writeFacts(prog, dir);
            prog->printAll(dir);
        }
        performSanityChecks(prog, vm.count("self-diagnose") != 0);
        delete prog;
    }
    else
    {
        std::cerr << "Failed to create instance for program <name>\n";
        return 1;
    }

    return 0;
}
