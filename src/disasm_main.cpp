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
#include <boost/uuid/uuid_generators.hpp>
#include <cstddef>
#include <fstream>
#include <gtirb/gtirb.hpp>
#include <iostream>
#include <string>
#include <utility>
#include <vector>
#include "BinaryReader.h"
#include "Dl_decoder.h"
#include "Elf_reader.h"
#include "ExceptionDecoder.h"
#include "GtirbModuleDisassembler.h"
#include "GtirbZeroBuilder.h"

namespace po = boost::program_options;
using namespace std::rel_ops;

static void decode(Dl_decoder &decoder, std::shared_ptr<BinaryReader> binary)
{
    for(const auto &codeSection : binary->get_code_sections())
    {
        if(auto section = binary->get_section_content_and_address(codeSection.name))
        {
            decoder.decode_section(std::get<0>(*section).data(), std::get<0>(*section).size(),
                                   std::get<1>(*section));
        }
    }
    uint64_t min_address = binary->get_min_address();
    uint64_t max_address = binary->get_max_address();
    for(const auto &dataSection : binary->get_non_zero_data_sections())
    {
        if(auto section = binary->get_section_content_and_address(dataSection.name))
        {
            decoder.store_data_section(std::get<0>(*section).data(), std::get<0>(*section).size(),
                                       std::get<1>(*section), min_address, max_address);
        }
    }
}

static void writeFacts(souffle::SouffleProgram *prog, const std::string &directory)
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

souffle::tuple &operator<<(souffle::tuple &t, const Dl_instruction &inst)
{
    t << inst.address << inst.size << inst.prefix << inst.name;
    for(size_t i = 0; i < 4; ++i)
    {
        if(i < inst.op_codes.size())
            t << inst.op_codes[i];
        else
            t << 0;
    }
    t << inst.immediateOffset << inst.displacementOffset;
    return t;
}

template <class T>
souffle::tuple &operator<<(souffle::tuple &t, const Dl_data<T> &data)
{
    t << data.ea << static_cast<int64_t>(data.content);
    return t;
}

souffle::tuple &operator<<(souffle::tuple &t, const std::pair<Dl_operator, int64_t> &pair)
{
    auto &[op, id] = pair;
    switch(op.type)
    {
        case NONE:
        default:
            break;
        case REG:
            t << id << op.reg1;
            break;
        case IMMEDIATE:
            t << id << op.offset;
            break;
        case INDIRECT:
            t << id << op.reg1 << op.reg2 << op.reg3 << op.multiplier << op.offset << op.size;
            break;
    }

    return t;
}

souffle::tuple &operator<<(souffle::tuple &t, const Section &section)
{
    t << section.name << section.size << section.address << section.type << section.flags;
    return t;
}

souffle::tuple &operator<<(souffle::tuple &t, const Symbol &symbol)
{
    t << symbol.address << symbol.size << symbol.type << symbol.scope << symbol.sectionIndex
      << symbol.name;
    return t;
}

souffle::tuple &operator<<(souffle::tuple &t, const Relocation &relocation)
{
    t << relocation.address << relocation.type << relocation.name << relocation.addend;
    return t;
}

template <typename T>
void addRelation(souffle::SouffleProgram *prog, const std::string &name, const std::vector<T> &data)
{
    auto *rel = prog->getRelation(name);
    for(const auto elt : data)
    {
        souffle::tuple t(rel);
        t << elt;
        rel->insert(t);
    }
}

static void loadInputs(souffle::SouffleProgram *prog, std::shared_ptr<BinaryReader> binary,
                       const Dl_decoder &decoder)
{
    addRelation<std::string>(prog, "binary_type", {binary->get_binary_type()});
    addRelation<std::string>(prog, "binary_format", {binary->get_binary_format()});
    addRelation<uint64_t>(prog, "entry_point", {binary->get_entry_point()});
    addRelation(prog, "section_complete", binary->get_sections());
    addRelation(prog, "symbol", binary->get_symbols());
    addRelation(prog, "relocation", binary->get_relocations());
    addRelation(prog, "instruction_complete", decoder.instructions);
    addRelation(prog, "address_in_data", decoder.data_addresses);
    addRelation(prog, "data_byte", decoder.data_bytes);
    addRelation(prog, "invalid_op_code", decoder.invalids);
    addRelation(prog, "op_regdirect", decoder.op_dict.get_operators_of_type(operator_type::REG));
    addRelation(prog, "op_immediate",
                decoder.op_dict.get_operators_of_type(operator_type::IMMEDIATE));
    addRelation(prog, "op_indirect",
                decoder.op_dict.get_operators_of_type(operator_type::INDIRECT));

    ExceptionDecoder excDecoder(binary);
    excDecoder.addExceptionInformation(prog);
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

    std::shared_ptr<BinaryReader> binary(new Elf_reader(filename));
    if(!binary->is_valid())
    {
        std::cerr << "There was a problem loading the binary file " << filename << "\n";
        return 1;
    }
    Dl_decoder decoder;
    decode(decoder, binary);
    std::cout << "Decoding the binary" << std::endl;
    if(souffle::SouffleProgram *prog = souffle::ProgramFactory::newInstance("souffle_disasm"))
    {
        try
        {
            loadInputs(prog, binary, decoder);
            std::cout << "Disassembling" << std::endl;
            prog->run();

            std::cout << "Building the gtirb representation" << std::endl;
            gtirb::Context context;
            gtirb::IR *ir = buildZeroIR(filename, binary, context);
            disassembleModule(context, *(ir->modules().begin()), binary, prog,
                              vm.count("self-diagnose") != 0);

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
            return 0;
        }
        catch(std::exception &e)
        {
            souffle::SignalHandler::instance()->error(e.what());
        }
    }
    else
    {
        std::cerr << "Failed to create instance for program <name>\n";
        return 1;
    }

    return 0;
}
