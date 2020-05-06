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
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <chrono>
#include <gtirb/gtirb.hpp>
#include <gtirb_pprinter/PrettyPrinter.hpp>
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include "AuxDataSchema.h"
#include "DatalogUtils.h"
#include "DlDecoder.h"
#include "GtirbModuleDisassembler.h"
#include "GtirbZeroBuilder.h"
#include "Version.h"
#include "passes/FunctionInferencePass.h"
#include "passes/NoReturnPass.h"
#include "passes/SccPass.h"

namespace fs = boost::filesystem;
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

void registerAuxDataTypes()
{
    using namespace gtirb::schema;
    gtirb::AuxDataContainer::registerAuxDataType<Comments>();
    gtirb::AuxDataContainer::registerAuxDataType<FunctionEntries>();
    gtirb::AuxDataContainer::registerAuxDataType<FunctionBlocks>();
    gtirb::AuxDataContainer::registerAuxDataType<FunctionNames>();
    gtirb::AuxDataContainer::registerAuxDataType<Padding>();
    gtirb::AuxDataContainer::registerAuxDataType<SymbolForwarding>();
    gtirb::AuxDataContainer::registerAuxDataType<ElfSymbolInfoAD>();
    gtirb::AuxDataContainer::registerAuxDataType<BinaryType>();
    gtirb::AuxDataContainer::registerAuxDataType<Sccs>();
    gtirb::AuxDataContainer::registerAuxDataType<Relocations>();
    gtirb::AuxDataContainer::registerAuxDataType<Encodings>();
    gtirb::AuxDataContainer::registerAuxDataType<ElfSectionProperties>();
    gtirb::AuxDataContainer::registerAuxDataType<ElfSectionIndex>();
    gtirb::AuxDataContainer::registerAuxDataType<PeSectionProperties>();
    gtirb::AuxDataContainer::registerAuxDataType<CfiDirectives>();
    gtirb::AuxDataContainer::registerAuxDataType<Libraries>();
    gtirb::AuxDataContainer::registerAuxDataType<LibraryPaths>();
    gtirb::AuxDataContainer::registerAuxDataType<DataDirectories>();
    gtirb::AuxDataContainer::registerAuxDataType<SymbolicExpressionSizes>();
}

void printElapsedTimeSince(std::chrono::time_point<std::chrono::high_resolution_clock> Start)
{
    auto End = std::chrono::high_resolution_clock::now();
    std::cout << " (";
    int secs = std::chrono::duration_cast<std::chrono::seconds>(End - Start).count();
    if(secs != 0)
        std::cout << secs << "s)" << std::endl;
    else
        std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(End - Start).count()
                  << "ms)" << std::endl;
}

std::vector<std::string> createDisasmOptions(const po::variables_map &vm)
{
    std::vector<std::string> Options;
    if(vm.count("no-cfi-directives"))
    {
        Options.push_back("no-cfi-directives");
    }
    return Options;
}
int main(int argc, char **argv)
{
    registerAuxDataTypes();

    po::options_description desc("Allowed options");
    desc.add_options()                                                  //
        ("help", "produce help message")                                //
        ("version", "display ddisasm version")                          //
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
        ("no-cfi-directives",
         "Do not produce cfi directives. Instead it produces symbolic expressions in .eh_frame.") //
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
        if(vm.count("version"))
        {
            std::cout << "v" << DDISASM_MAJOR_VERSION << "." << DDISASM_MINOR_VERSION << "."
                      << DDISASM_PATCH_VERSION << "\n";
            return EXIT_SUCCESS;
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
    if(!fs::exists(filename))
    {
        std::cerr << "Error: input binary " << filename << " does not exist" << std::endl;
        return 1;
    }

    std::cout << "Building the initial gtirb representation " << std::flush;
    gtirb::Context context;

    auto StartBuildZeroIR = std::chrono::high_resolution_clock::now();
    gtirb::IR *ir = buildZeroIR(filename, context);
    printElapsedTimeSince(StartBuildZeroIR);

    if(!ir)
    {
        std::cerr << "There was a problem loading the binary file " << filename << "\n";
        return 1;
    }
    gtirb::Module &module = *(ir->modules().begin());
    souffle::SouffleProgram *prog;
    {
        DlDecoder decoder;
        std::cout << "Decoding the binary " << std::flush;
        auto StartDecode = std::chrono::high_resolution_clock::now();
        std::vector<std::string> DisasmOptions = createDisasmOptions(vm);
        prog = decoder.decode(module, DisasmOptions);
        printElapsedTimeSince(StartDecode);
    }
    if(prog)
    {
        std::cout << "Disassembling " << std::flush;
        unsigned int NThreads = vm["threads"].as<unsigned int>();
        prog->setNumThreads(NThreads);
        auto StartDisassembling = std::chrono::high_resolution_clock::now();
        try
        {
            prog->run();
        }
        catch(std::exception &e)
        {
            souffle::SignalHandler::instance()->error(e.what());
        }
        printElapsedTimeSince(StartDisassembling);
        std::cout << "Populating gtirb representation " << std::flush;
        auto StartGtirbBuilding = std::chrono::high_resolution_clock::now();
        disassembleModule(context, module, prog, vm.count("self-diagnose") != 0);
        printElapsedTimeSince(StartGtirbBuilding);

        if(vm.count("skip-function-analysis") == 0)
        {
            std::cout << "Computing intra-procedural SCCs " << std::flush;
            auto StartSCCsComputation = std::chrono::high_resolution_clock::now();
            computeSCCs(module);
            printElapsedTimeSince(StartSCCsComputation);
            std::cout << "Computing no return analysis " << std::flush;
            NoReturnPass NoReturn;
            FunctionInferencePass FunctionInference;
            if(vm.count("debug-dir") != 0)
            {
                NoReturn.setDebugDir(vm["debug-dir"].as<std::string>() + "/");
                FunctionInference.setDebugDir(vm["debug-dir"].as<std::string>() + "/");
            }
            auto StartNoReturnAnalysis = std::chrono::high_resolution_clock::now();
            NoReturn.computeNoReturn(module, NThreads);
            printElapsedTimeSince(StartNoReturnAnalysis);
            std::cout << "Detecting additional functions " << std::flush;
            auto StartFunctionAnalysis = std::chrono::high_resolution_clock::now();
            FunctionInference.computeFunctions(context, module, NThreads);
            printElapsedTimeSince(StartFunctionAnalysis);
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
                pprinter.symbolPolicy().keep(keep);
            }
        }
        if(vm.count("asm") != 0)
        {
            std::cout << "Printing assembler " << std::flush;
            auto StartPrinting = std::chrono::high_resolution_clock::now();
            std::ofstream out(vm["asm"].as<std::string>());
            pprinter.print(out, context, module);
            printElapsedTimeSince(StartPrinting);
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
