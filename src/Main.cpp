//===- Main.cpp -------------------------------------------------*- C++ -*-===//
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
#include <fcntl.h>

#include <chrono>
#include <iomanip>
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
#include <gtirb_pprinter/Fixup.hpp>
#include <gtirb_pprinter/PeBinaryPrinter.hpp>
#include <gtirb_pprinter/PrettyPrinter.hpp>

#include "AnalysisPipeline.h"
#include "AuxDataSchema.h"
#include "CliDriver.h"
#include "Hints.h"
#include "Registration.h"
#include "Version.h"
#include "gtirb-builder/GtirbBuilder.h"
#include "passes/DisassemblyPass.h"
#include "passes/FunctionInferencePass.h"
#include "passes/NoReturnPass.h"
#include "passes/SccPass.h"

namespace fs = boost::filesystem;
namespace po = boost::program_options;

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

bool isPEFormat(const gtirb::IR &IR)
{
    auto Modules = IR.modules();
    for(auto &Module : Modules)
    {
        if(Module.getFileFormat() == gtirb::FileFormat::PE)
        {
            return true;
        }
    }
    return false;
}

static void checkPathIsWritable(const std::string &Path)
{
    std::ofstream Out(Path, std::ios::out);
    if(!Out.is_open())
    {
        std::cerr << "Error: failed to open file: " << Path << "\n";
        std::exit(1);
    }
}

static void checkOutputParamIsWritable(const po::variables_map &Vars, const std::string &VarName)
{
    if(Vars.count(VarName) != 0)
    {
        std::string Path = Vars[VarName].as<std::string>();
        if(Path != "-")
        {
            checkPathIsWritable(Path);
        }
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
        "hints", po::value<std::string>(), "location of user-provided hints file")(
        "input-file", po::value<std::string>(), "file to disasemble")(
        "ignore-errors", "Return success even if there are disassembly errors.")(
        "keep-functions,K", po::value<std::vector<std::string>>()->multitoken(),
        "Print the given functions even if they are skipped by default (e.g. _start)")(
        "self-diagnose",
        "Use relocation information to emit a self diagnose of the symbolization process. This "
        "option only works if the target binary contains complete relocation information.")(
        "skip-function-analysis,F",
        "Skip additional analyses to compute more precise function boundaries.")(
        "with-souffle-relations", "Package facts/output relations into an AuxData table.")(
        "no-cfi-directives",
        "Do not produce cfi directives. Instead it produces symbolic expressions in .eh_frame "
        "(this functionality is experimental and does not produce reliable results).")(
        "threads,j", po::value<unsigned int>()->default_value(1), "Number of cores to use.")(
        "generate-import-libs", "Generated .DEF and .LIB files for imported libraries (PE).")(
        "generate-resources", "Generated .RES files for embedded resources (PE).")(
        "no-analysis,n",
        "Do not perform disassembly. This option only parses/loads the binary object into GTIRB.")(
        "interpreter,I", po::value<std::string>()->implicit_value("."),
        "Execute the souffle interpreter with the specified repository root directory.")(
        "library-dir,L", po::value<std::string>(),
        "Directory from which extra libraries are loaded when running the interpreter")(
        "profile", po::value<std::string>()->default_value(""),
        "Generate Souffle profiling information in the specified directory.");

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

    const std::string &ProfileDir = vm["profile"].as<std::string>();
#if !defined(DDISASM_SOUFFLE_PROFILING)
    if(!ProfileDir.empty() && !vm.count("interpreter"))
    {
        std::cerr << "Error: missing `--interpreter' argument required by `--profile'\n";
        return 1;
    }
#endif

    checkOutputParamIsWritable(vm, "ir");
    checkOutputParamIsWritable(vm, "json");

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

    auto Modules = GTIRB->IR->modules();
    unsigned int ModuleCount = std::distance(std::begin(Modules), std::end(Modules));
    if(vm.count("asm") != 0)
    {
        // We don't know whether we will be creating a directory and writing
        // multiple --asm files or writing a single file until we have created
        // the initial GTIRB.
        // Ensure the output file is writable if we're just doing a single file.
        if(ModuleCount == 1)
        {
            checkOutputParamIsWritable(vm, "asm");
        }
    }

    // Add `ddisasmVersion' aux data table.
    GTIRB->IR->addAuxData<gtirb::schema::DdisasmVersion>(DDISASM_FULL_VERSION_STRING);
    printElapsedTimeSince(StartBuildZeroIR);
    std::cerr << "\n";

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

    AnalysisPipeline Pipeline;
    Pipeline.addListener(std::make_shared<DDisasmPipelineListener>());
    Pipeline.push<DisassemblyPass>(vm.count("self-diagnose") != 0, vm.count("ignore-errors") != 0,
                                   vm.count("no-cfi-directives") != 0);

    if(vm.count("skip-function-analysis") == 0)
    {
        Pipeline.push<SccPass>();
        Pipeline.push<NoReturnPass>();
        Pipeline.push<FunctionInferencePass>();
    }

    Pipeline.setDatalogThreadCount(vm["threads"].as<unsigned int>());
    if(!ProfileDir.empty())
    {
        fs::create_directories(ProfileDir);
        Pipeline.setDatalogProfileDir(ProfileDir);
    }

    if(vm.count("debug-dir"))
    {
        Pipeline.configureDebugDir(vm["debug-dir"].as<std::string>(), ModuleCount > 1);
    }

    if(vm.count("interpreter"))
    {
        Pipeline.configureSouffleInterpreter(
            vm["interpreter"].as<std::string>(),
            vm.count("library-dir") ? vm["library-dir"].as<std::string>() : std::string());
    }

    // TODO: currently, hints files have no support for static archives containing multiple modules;
    // all hints are used when processing each module, which is most likely not desirable.
    if(vm.count("hints"))
    {
        Pipeline.loadHints(vm["hints"].as<std::string>());
    }

    if(vm.count("with-souffle-relations"))
    {
        Pipeline.enableSouffleOutputs();
    }

    for(auto &Module : Modules)
    {
        std::cerr << "Processing module: " << Module.getName() << "\n";
        Pipeline.run(*GTIRB->Context, Module);

        // Remove provisional AuxData tables.
        Module.removeAuxData<gtirb::schema::Relocations>();
        Module.removeAuxData<gtirb::schema::SectionIndex>();
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
            std::ofstream out(name);
            GTIRB->IR->saveJSON(out);
        }
    }

    gtirb_pprint::PrettyPrinter pprinter;

    // Output PE-specific build artifacts.
    if(isPEFormat(*GTIRB->IR))
    {
        for(auto &Module : Modules)
        {
            if(vm.count("generate-import-libs"))
            {
                gtirb_bprint::PeBinaryPrinter BP(pprinter, {}, {});
                BP.libs(Module);
            }
            if(vm.count("generate-resources"))
            {
                gtirb_bprint::PeBinaryPrinter BP(pprinter, {}, {});
                BP.resources(Module, *GTIRB->Context);
            }
        }
    }

    // Pretty-print
    if(vm.count("asm") != 0 || (vm.count("ir") == 0 && vm.count("json") == 0))
    {
        std::string ListingMode = vm.count("debug") != 0 ? "debug" : "";
        for(auto &Module : Modules)
        {
            const std::string &format = gtirb_pprint::getModuleFileFormat(Module);
            const std::string &isa = gtirb_pprint::getModuleISA(Module);
            const std::string &syntax =
                gtirb_pprint::getDefaultSyntax(format, isa, ListingMode).value_or("");
            auto target = std::make_tuple(format, isa, syntax);
            pprinter.setTarget(std::move(target));

            // Apply pre-print transforms provided by the pretty-printer library.
            // This MODIFIES the GTIRB, so it's important to do this *after*
            // writing the GTIRB output to disk if we're doing both.
            gtirb_pprint::applyFixups(*GTIRB->Context, Module, pprinter);

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

            fs::path AsmPath;
            std::ofstream AsmFileStream;
            bool UseStdout = true;
            if(vm.count("asm") != 0)
            {
                std::string name = vm["asm"].as<std::string>();
                if(name != "-")
                {
                    AsmPath = name;
                }
            }

            if(!AsmPath.empty())
            {
                // If there are multiple modules, use the asm argument as a directory.
                // Each module will get its own .s file.
                if(ModuleCount > 1)
                {
                    fs::create_directories(AsmPath);
                    std::string name = Module.getName();

                    // Strip ".o" extension if it exists.
                    if(name.compare(name.size() - 2, 2, ".o") == 0)
                    {
                        name.erase(name.size() - 2);
                    }
                    AsmPath /= name + ".s";
                }
                AsmFileStream.open(AsmPath.string());
                UseStdout = false;
            }

            std::cerr << "Printing assembler " << std::flush;
            auto StartPrinting = std::chrono::high_resolution_clock::now();
            pprinter.print(UseStdout ? std::cout : AsmFileStream, *GTIRB->Context, Module);
            printElapsedTimeSince(StartPrinting);
            std::cerr << "\n";
        }
    }

    if(GTIRB)
    {
        GTIRB->Context->ForgetAllocations();
    }

    return EXIT_SUCCESS;
}
