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
#include "AuxDataSchema.h"
#include "DatalogUtils.h"
#include "X86Decoder.h"
#include "AArch64Decoder.h"
#include "GtirbModuleDisassembler.h"
#include "GtirbZeroBuilder.h"
#include "passes/FunctionInferencePass.h"
#include "passes/NoReturnPass.h"
#include "passes/SccPass.h"
#include "DwarfMap.hpp"

#ifdef USE_STD_FILESYSTEM_LIB
#include <filesystem>
namespace fs = std::filesystem;
#else
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
#endif // USE_STD_FILESYSTEM_LIB

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

//TODO: Move this function to another part
std::optional<DlDecoder*> make_decoder(LIEF::ARCHITECTURES arch) {
    if(arch == LIEF::ARCHITECTURES::ARCH_X86) {
        return std::make_optional(new X86Decoder());
    } else if(arch == LIEF::ARCHITECTURES::ARCH_ARM64) {
        return std::make_optional(new AArch64Decoder());
    } else {
        //DEFAULT TO X86 for now
        return std::nullopt;
    }
}

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
    gtirb::AuxDataContainer::registerAuxDataType<SymbolicOperandInfoAD>();
    gtirb::AuxDataContainer::registerAuxDataType<Encodings>();
    gtirb::AuxDataContainer::registerAuxDataType<ElfSectionProperties>();
    gtirb::AuxDataContainer::registerAuxDataType<AllElfSectionProperties>();
    gtirb::AuxDataContainer::registerAuxDataType<DWARFElfSectionProperties>();
    gtirb::AuxDataContainer::registerAuxDataType<PeSectionProperties>();
    gtirb::AuxDataContainer::registerAuxDataType<CfiDirectives>();
    gtirb::AuxDataContainer::registerAuxDataType<Libraries>();
    gtirb::AuxDataContainer::registerAuxDataType<LibraryPaths>();
    gtirb::AuxDataContainer::registerAuxDataType<DataDirectories>();
}

int main(int argc, char **argv)
{
    registerAuxDataTypes();

    po::options_description desc("Allowed options");
    desc.add_options()                                                  //
        ("help", "produce help message")                                //
        ("ir", po::value<std::string>(), "GTIRB output file")           //
        ("json", po::value<std::string>(), "GTIRB json output file")    //
        ("asm", po::value<std::string>(), "ASM output file")            //
        ("dwarf", "Dwarf analysis")
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
    if(!fs::exists(filename))
    {
        std::cerr << "Error: input binary " << filename << " does not exist" << std::endl;
        return 1;
    }

    std::cout << "Building the initial gtirb representation" << std::endl;
    gtirb::Context context;
    gtirb::IR *ir = nullptr;
    LIEF::ARCHITECTURES lief_arch;
    LIEF::ENDIANNESS endianness;
    std::tie(ir, lief_arch, endianness) = buildZeroIR(filename, context);

    if(!ir)
    {
        std::cerr << "There was a problem loading the binary file " << filename << "\n";
        return 1;
    }
    gtirb::Module &module = *(ir->modules().begin());
    souffle::SouffleProgram *prog = nullptr;

    cs_arch arch;
    cs_mode mode;
    if(std::optional<DlDecoder*> dec = make_decoder(lief_arch)) {
        DlDecoder* decoder = *dec;
        std::cout << "Decoding the binary" << std::endl;
        prog = decoder->decode(module);
        arch = decoder->getArch();
        mode = decoder->getMode();
        delete decoder;
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
            NoReturn.computeNoReturn(module, arch, mode, NThreads);
            std::cout << "Detecting additional functions" << std::endl;
            FunctionInference.computeFunctions(context, module, arch, mode, NThreads);
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

        std::tuple<std::string, std::string> target;
        if (arch == CS_ARCH_X86) {
            target = std::tuple<std::string, std::string>("elf", "intel");
        } else if (arch == CS_ARCH_ARM64) {
            target = std::tuple<std::string, std::string>("elf", "aarch64");
        } else {
            assert(false && "unsupported architecture");
        }
        pprinter.setTarget(target);

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
