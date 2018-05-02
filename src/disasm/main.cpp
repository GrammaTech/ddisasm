#include <boost/program_options.hpp>
#include <iomanip>
#include <iostream>
#include "DisasmData.h"
#include "PrettyPrinter.h"

int main(int argc, char** argv)
{
    boost::program_options::options_description desc("Allowed options");
    desc.add_options()("help", "Produce help message.");
    desc.add_options()("dir,d", boost::program_options::value<std::string>(),
                       "Set a datalog output directory to parse.");
    desc.add_options()("asm,a", boost::program_options::value<std::string>()->default_value("out.asm"),
                       "The name of the assembly output file.");
    desc.add_options()("debug,D", boost::program_options::value<bool>()->default_value(false),
                       "Turn on debugging (will break assembly)");

    boost::program_options::variables_map vm;
    boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc), vm);

    if(vm.count("help") || argc == 1)
    {
        std::cout << desc << "\n";
        return 1;
    }

    boost::program_options::notify(vm);

    DisasmData disasm;

    if(vm.count("dir"))
    {
        auto value = vm["dir"].as<std::string>();
        std::cerr << std::setw(24) << std::left << "Reading Directory: "
                  << "\"" << value << "\"" << std::endl;
        disasm.parseDirectory(value);
    }

    // if(vm.count("asm"))
    //{
    //  auto value = vm["asm"].as<std::string>();
    //  std::cerr << std::setw(24) << std::left << "Saving ASM: " << "\"" << value << "\"" <<
    // std::endl;

    PrettyPrinter pp;
    pp.setDebug(vm["debug"].as<bool>());

    auto assembly = pp.prettyPrint(&disasm);

    std::cout << assembly << std::endl;
    //}
}
