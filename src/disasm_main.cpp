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
#include <PrettyPrinter.h>
#include <souffle/CompiledSouffle.h>
#include <souffle/SouffleInterface.h>
#include <boost/program_options.hpp>
#include <gtirb/gtirb.hpp>
#include <iostream>
#include <string>
#include <vector>
#include "DlDecoder.h"
#include "GtirbModuleDisassembler.h"
#include "GtirbZeroBuilder.h"

namespace po = boost::program_options;

void writeFacts(souffle::SouffleProgram *prog, const std::string &directory)
{
    std::ios_base::openmode filemask = std::ios::out;
    for(souffle::Relation *relation : prog->getInputRelations())
    {
        std::ofstream file(directory + relation->getName() + ".facts", filemask);
        souffle::SymbolTable symbolTable = relation->getSymbolTable();
        for(souffle::tuple tuple : *relation)
        {
            for(size_t i = 0; i < tuple.size(); i++)
            {
                if(i > 0)
                    file << "\t";
                if(relation->getAttrType(i)[0] == 's')
                    file << symbolTable.resolve(tuple[i]);
                else
                    file << tuple[i];
            }
            file << std::endl;
        }
        file.close();
    }
}

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
        ("input-file", po::value<std::string>(), "file to disasemble")(
            "keep-functions,K",
            boost::program_options::value<std::vector<std::string>>()->multitoken(),
            "Print the given functions even if they are skipped by default (e.g. _start)")(
            "self-diagnose",
            "Use relocation information to emit a self diagnose of the symbolization process. This "
            "option only works if the target binary contains complete relocation information.");
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

        // Output GTIRB
        if(vm.count("ir") != 0)
        {
            std::ofstream out(vm["ir"].as<std::string>());
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
            pprinter.print(out, context, *ir);
        }
        else if(vm.count("ir") == 0)
        {
            std::cout << "Printing assembler" << std::endl;
            pprinter.print(std::cout, context, *ir);
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
