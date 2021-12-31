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
#include <gtirb_pprinter/PeBinaryPrinter.hpp>
#include <gtirb_pprinter/PrettyPrinter.hpp>

#include "AuxDataSchema.h"
#include "Disassembler.h"
#include "Interpreter.h"
#include "Registration.h"
#include "Version.h"
#include "gtirb-builder/GtirbBuilder.h"
#include "gtirb-decoder/DatalogProgram.h"
#include "gtirb-decoder/core/ModuleLoader.h"
#include "passes/FunctionInferencePass.h"
#include "passes/NoReturnPass.h"
#include "passes/SccPass.h"

namespace fs = boost::filesystem;
namespace po = boost::program_options;

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
        "with-souffle-relations", "Package facts/output relations into an AuxData table.")(
        "no-cfi-directives",
        "Do not produce cfi directives. Instead it produces symbolic expressions in .eh_frame.")(
        "threads,j", po::value<unsigned int>()->default_value(1),
        "Number of cores to use. It is set to the number of cores in the machine by default")(
        "generate-import-libs", "Generated .DEF and .LIB files for imported libraries (PE).")(
        "generate-resources", "Generated .RES files for embedded resources (PE).")(
        "no-analysis,n",
        "Do not perform disassembly. This option only parses/loads the binary object into GTIRB.")(
        "interpreter,I", po::value<std::string>(),
        "Execute the souffle interpreter with the specified source file.");

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

    // TODO: Use a temporary directory if `--debug-dir' isn't specified.
    if(vm.count("interpreter") && !vm.count("debug-dir"))
    {
        std::cerr << "Error: missing `--debug-dir' argument required by `--interpreter'\n";
        return 1;
    }

    // Parse and build a GTIRB module from a supported binary object file.
    std::cerr << "Building the initial gtirb representation " << std::flush;
    auto StartBuildZeroIR = std::chrono::high_resolution_clock::now();
    std::string Filename = vm["input-file"].as<std::string>();
    auto GTIRB = GtirbBuilder::read(Filename);
    if(!GTIRB)
    {
        std::cerr << "\nERROR: " << Filename << ": " << GTIRB.getError().message() << "\n";
        return 1;
    }

    // Add `ddisasmVersion' aux data table.
    GTIRB->IR->addAuxData<gtirb::schema::DdisasmVersion>(DDISASM_FULL_VERSION_STRING);
    printElapsedTimeSince(StartBuildZeroIR);

    if(!GTIRB->IR)
    {
        std::cerr << "There was a problem loading the binary file " << Filename << "\n";
        return 1;
    }

    // Output raw GTIRB file.
    if(vm.count("no-analysis") && vm.count("ir"))
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
        return 0;
    }

    auto Modules = GTIRB->IR->modules();
    unsigned int ModuleCount = std::distance(std::begin(Modules), std::end(Modules));
    for(auto &Module : Modules)
    {
        // Decode and load GTIRB Module into the SouffleProgram context.
        std::cerr << "Decoding binary: " << Module.getName() << std::flush;
        auto StartDecode = std::chrono::high_resolution_clock::now();

        std::optional<DatalogProgram> Souffle = DatalogProgram::load(Module);
        if(!Souffle)
        {
            std::cerr << "\nERROR: " << Filename << ": "
                      << "Unsupported binary target: " << binaryFormat(Module.getFileFormat())
                      << "-" << binaryISA(Module.getISA()) << "-"
                      << binaryEndianness(Module.getByteOrder()) << "\n\n";

            std::cerr << "Available targets:\n";
            for(auto [FileFormat, Arch, ByteOrder] : DatalogProgram::supportedTargets())
            {
                std::cerr << "\t" << binaryFormat(FileFormat) << "-" << binaryISA(Arch) << "-"
                          << binaryEndianness(ByteOrder) << "\n";
            }
            return EXIT_FAILURE;
        }

        printElapsedTimeSince(StartDecode);

        // Remove initial entry point.
        if(gtirb::CodeBlock *Block = Module.getEntryPoint())
        {
            Block->getByteInterval()->removeBlock(Block);
        }
        Module.setEntryPoint(nullptr);

        Souffle->insert("option", createDisasmOptions(vm));

        fs::path DebugDir;
        if(vm.count("debug-dir") != 0)
        {
            // Create multiple subdirectories for each module, if there are multiple.
            DebugDir = vm["debug-dir"].as<std::string>();
            if(ModuleCount > 1)
            {
                DebugDir /= Module.getName();
            }

            std::cerr << "Writing facts to debug dir " << vm["debug-dir"].as<std::string>()
                      << std::endl;
            fs::create_directories(DebugDir);
            Souffle->writeFacts(DebugDir.string() + "/");
        }
        if(vm.count("with-souffle-relations"))
        {
            Souffle->writeFacts(Module);
        }

        std::cerr << "Disassembling" << std::flush;
        unsigned int Threads = vm["threads"].as<unsigned int>();

        auto StartDisassembling = std::chrono::high_resolution_clock::now();
        if(vm.count("interpreter"))
        {
            // Disassemble with the interpeter engine.
            std::cerr << " (interpreter)";
            const std::string &DatalogFile = vm["interpreter"].as<std::string>();
            runInterpreter(Module, Souffle->get(), DatalogFile, DebugDir.string(), Threads);
        }
        else
        {
            // Disassemble with the compiled, synthesized program.
            Souffle->threads(Threads);
            try
            {
                Souffle->run();
            }
            catch(std::exception &e)
            {
                souffle::SignalHandler::instance()->error(e.what());
            }
        }
        printElapsedTimeSince(StartDisassembling);

        if(!DebugDir.empty())
        {
            std::cerr << "Writing results to debug dir " << DebugDir << std::endl;
            Souffle->writeRelations(DebugDir.string() + "/");
        }
        if(vm.count("with-souffle-relations"))
        {
            Souffle->writeRelations(Module);
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

            if(!DebugDir.empty())
            {
                fs::path PassDir;
                PassDir = DebugDir / "pass-noreturn";
                fs::create_directories(PassDir);
                NoReturn.setDebugDir(PassDir.string() + "/");

                PassDir = DebugDir / "pass-function-inference";
                fs::create_directories(PassDir);
                FunctionInference.setDebugDir(PassDir.string() + "/");
            }
            auto StartNoReturnAnalysis = std::chrono::high_resolution_clock::now();
            NoReturn.computeNoReturn(Module, Threads);
            printElapsedTimeSince(StartNoReturnAnalysis);
            std::cerr << "Detecting additional functions " << std::flush;
            auto StartFunctionAnalysis = std::chrono::high_resolution_clock::now();
            FunctionInference.computeFunctions(*GTIRB->Context, Module, Threads);
            printElapsedTimeSince(StartFunctionAnalysis);
        }

        // Remove provisional AuxData tables.
        Module.removeAuxData<gtirb::schema::Relocations>();
        Module.removeAuxData<gtirb::schema::ElfSectionIndex>();

        // Pretty-print
        gtirb_pprint::PrettyPrinter pprinter;
        if(vm.count("debug") != 0)
        {
            pprinter.setListingMode("debug");
        }

        if(vm.count("keep-functions") != 0)
        {
            for(auto keep : vm["keep-functions"].as<std::vector<std::string>>())
            {
                pprinter.symbolPolicy().keep(keep);
            }
        }

        // TODO: combine asm code and no args code.
        if(vm.count("asm") != 0)
        {
            // TODO: print all modules? can we create separate .s files for each module?

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

        // TODO: is this something that should really be done per-module?
        // Output PE-specific build artifacts.
        if(Module.getFileFormat() == gtirb::FileFormat::PE)
        {
            if(vm.count("generate-import-libs"))
            {
                gtirb_bprint::PeBinaryPrinter BP(pprinter, {}, {});
                BP.libs(*GTIRB->IR);
            }
            if(vm.count("generate-resources"))
            {
                gtirb_bprint::PeBinaryPrinter BP(pprinter, {}, {});
                BP.resources(*GTIRB->IR, *GTIRB->Context);
            }
        }
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

    if(GTIRB)
    {
        GTIRB->Context->ForgetAllocations();
    }

    return 0;
}
