//===- Main.cpp -------------------------------------------------*- C++ -*-===//
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
#include <fcntl.h>

#include <chrono>
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#if defined(_MSC_VER)
#include <io.h>
#endif
#if defined(__unix__)
#include <unistd.h>
#endif

#include <souffle/CompiledSouffle.h>
#include <souffle/SouffleInterface.h>

#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <gtirb/gtirb.hpp>
#include <gtirb_pprinter/PrettyPrinter.hpp>

#include "AuxDataSchema.h"
#include "Disassembler.h"
#include "Registration.h"
#include "Version.h"
#include "gtirb-builder/GtirbBuilder.h"
#include "gtirb-decoder/DatalogProgram.h"
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

void printElapsedTimeSince(std::chrono::time_point<std::chrono::high_resolution_clock> Start)
{
    auto End = std::chrono::high_resolution_clock::now();
    std::cerr << " (";
    int64_t secs = std::chrono::duration_cast<std::chrono::seconds>(End - Start).count();
    if(secs != 0)
        std::cerr << secs << "s)" << std::endl;
    else
        std::cerr << std::chrono::duration_cast<std::chrono::milliseconds>(End - Start).count()
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

static bool isStdoutATerminal()
{
#if defined(_MSC_VER)
    return _isatty(_fileno(stdout));
#else
    return isatty(fileno(stdout));
#endif
}

static void setStdoutToBinary()
{
    // Check to see if we're running a tty vs a pipe. If a tty, then we
    // want to warn the user if we're going to open in binary mode.
    if(isStdoutATerminal())
    {
        std::cerr << "Refusing to set stdout to binary mode when stdout is a terminal\n";
    }
    else
    {
#if defined(_MSC_VER)
        _setmode(_fileno(stdout), _O_BINARY);
#else
        stdout = freopen(NULL, "wb", stdout);
        assert(stdout && "Failed to reopen stdout");
#endif
    }
}

int main(int argc, char **argv)
{
    registerAuxDataTypes();
    registerDatalogLoaders();
    gtirb_pprint::registerPrettyPrinters();

    po::options_description desc("Allowed options");
    desc.add_options()("help,h", "produce help message")("version", "display ddisasm version")(
        "ir", po::value<std::string>()->implicit_value("-"),
        "Specifies the GTIRB output file; use '-' to print to stdout")(
        "json", po::value<std::string>()->implicit_value("-"),
        "Specifies the GTIRB json output file; use '-' to print to stdout")(
        "asm", po::value<std::string>()->implicit_value("-"),
        "Specifies the ASM output file; use to '-' print to stdout")(
        "debug", "generate assembler file with debugging information")(
        "debug-dir", po::value<std::string>(), "location to write CSV files for debugging")(
        "input-file", po::value<std::string>(), "file to disasemble")(
        "keep-functions,K", po::value<std::vector<std::string>>()->multitoken(),
        "Print the given functions even if they are skipped by default (e.g. _start)")(
        "self-diagnose",
        "Use relocation information to emit a self diagnose of the symbolization process. This "
        "option only works if the target binary contains complete relocation information.")(
        "skip-function-analysis,F",
        "Skip additional analyses to compute more precise function boundaries.")(
        "no-cfi-directives",
        "Do not produce cfi directives. Instead it produces symbolic expressions in .eh_frame.")(
        "threads,j", po::value<unsigned int>()->default_value(std::thread::hardware_concurrency()),
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
            std::cout << DDISASM_FULL_VERSION_STRING << "\n";
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

    // Parse and build a GTIRB module from a supported binary object file.
    std::cerr << "Building the initial gtirb representation " << std::flush;
    auto StartBuildZeroIR = std::chrono::high_resolution_clock::now();
    std::string filename = vm["input-file"].as<std::string>();
    auto GTIRB = GtirbBuilder::read(filename);
    if(!GTIRB)
    {
        std::cerr << "\nERROR: " << filename << ": " << GTIRB.getError().message() << "\n";
        return 1;
    }

    // Add `ddisasmVersion' aux data table.
    GTIRB->IR->addAuxData<gtirb::schema::DdisasmVersion>(DDISASM_FULL_VERSION_STRING);
    printElapsedTimeSince(StartBuildZeroIR);

    if(!GTIRB->IR)
    {
        std::cerr << "There was a problem loading the binary file " << filename << "\n";
        return 1;
    }

    // Decode and load GTIRB Module into the SouffleProgram context.
    std::cerr << "Decoding the binary " << std::flush;
    auto StartDecode = std::chrono::high_resolution_clock::now();

    gtirb::Module &Module = *(GTIRB->IR->modules().begin());
    std::optional<DatalogProgram> Souffle = DatalogProgram::load(Module);

    printElapsedTimeSince(StartDecode);

    // Remove initial entry point.
    if(gtirb::CodeBlock *Block = Module.getEntryPoint())
    {
        Block->getByteInterval()->removeBlock(Block);
    }
    Module.setEntryPoint(nullptr);

    // Remove placeholder relocation data.
    Module.removeAuxData<gtirb::schema::Relocations>();

    if(Souffle)
    {
        Souffle->insert("option", createDisasmOptions(vm));

        if(vm.count("debug-dir") != 0)
        {
            std::cerr << "Writing facts to debug dir " << vm["debug-dir"].as<std::string>()
                      << std::endl;
            auto dir = vm["debug-dir"].as<std::string>() + "/";
            Souffle->writeFacts(dir);
        }
        std::cerr << "Disassembling" << std::flush;
        unsigned int NThreads = vm["threads"].as<unsigned int>();
        Souffle->threads(NThreads);
        auto StartDisassembling = std::chrono::high_resolution_clock::now();
        try
        {
            Souffle->run();
        }
        catch(std::exception &e)
        {
            souffle::SignalHandler::instance()->error(e.what());
        }
        printElapsedTimeSince(StartDisassembling);
        if(vm.count("debug-dir") != 0)
        {
            std::cerr << "Writing results to debug dir " << vm["debug-dir"].as<std::string>()
                      << std::endl;
            auto dir = vm["debug-dir"].as<std::string>() + "/";
            Souffle->writeRelations(dir);
        }
        std::cerr << "Populating gtirb representation " << std::flush;
        auto StartGtirbBuilding = std::chrono::high_resolution_clock::now();
        disassembleModule(*GTIRB->Context, Module, Souffle->get(), vm.count("self-diagnose") != 0);
        printElapsedTimeSince(StartGtirbBuilding);

        if(vm.count("skip-function-analysis") == 0)
        {
            std::cerr << "Computing intra-procedural SCCs " << std::flush;
            auto StartSCCsComputation = std::chrono::high_resolution_clock::now();
            computeSCCs(Module);
            printElapsedTimeSince(StartSCCsComputation);
            std::cerr << "Computing no return analysis " << std::flush;
            NoReturnPass NoReturn;
            FunctionInferencePass FunctionInference;
            if(vm.count("debug-dir") != 0)
            {
                NoReturn.setDebugDir(vm["debug-dir"].as<std::string>() + "/");
                FunctionInference.setDebugDir(vm["debug-dir"].as<std::string>() + "/");
            }
            auto StartNoReturnAnalysis = std::chrono::high_resolution_clock::now();
            NoReturn.computeNoReturn(Module, NThreads);
            printElapsedTimeSince(StartNoReturnAnalysis);
            std::cerr << "Detecting additional functions " << std::flush;
            auto StartFunctionAnalysis = std::chrono::high_resolution_clock::now();
            FunctionInference.computeFunctions(*GTIRB->Context, Module, NThreads);
            printElapsedTimeSince(StartFunctionAnalysis);
        }
        // Output GTIRB
        if(vm.count("ir") != 0)
        {
            std::string name = vm["ir"].as<std::string>();
            if(name == "-")
            {
                setStdoutToBinary();
                GTIRB->IR->save(std::cout);
            }
            else
            {
                std::ofstream out(name, std::ios::out | std::ios::binary);
                GTIRB->IR->save(out);
            }
        }
        // Output json GTIRB
        if(vm.count("json") != 0)
        {
            std::string name = vm["json"].as<std::string>();
            if(name == "-")
            {
                GTIRB->IR->saveJSON(std::cout);
            }
            else
            {
                std::ofstream out(vm["json"].as<std::string>());
                GTIRB->IR->saveJSON(out);
            }
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
            std::cerr << "Printing assembler " << std::flush;
            auto StartPrinting = std::chrono::high_resolution_clock::now();
            std::string name = vm["asm"].as<std::string>();
            if(name == "-")
            {
                pprinter.print(std::cout, *GTIRB->Context, Module);
            }
            else
            {
                std::ofstream out(name);
                pprinter.print(out, *GTIRB->Context, Module);
            }
            printElapsedTimeSince(StartPrinting);
        }
        else if(vm.count("ir") == 0 && vm.count("json") == 0)
        {
            std::cerr << "Printing assembler" << std::endl;
            pprinter.print(std::cout, *GTIRB->Context, Module);
        }
        performSanityChecks(Souffle->get(), vm.count("self-diagnose") != 0);
    }
    else
    {
        std::cerr << "Failed to create instance for program <name>\n";
        return 1;
    }

    return 0;
}
