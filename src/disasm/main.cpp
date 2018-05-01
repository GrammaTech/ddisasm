#include <boost/program_options.hpp>
#include <iomanip>
#include <iostream>
#include "DisasmData.h"
#include "PrettyPrinter.h"

int main(int argc, char** argv)
{
    boost::program_options::options_description desc("Allowed options");
    desc.add_options()("help", "Produce help message.")(
        "dir", boost::program_options::value<std::string>(), "Set the directory to parse.")(
        "asm", boost::program_options::value<std::string>(),
        "Set the name of the assembly file to print to.");

    boost::program_options::variables_map vm;
    boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc), vm);
    boost::program_options::notify(vm);

    if(vm.count("help") || argc < 2)
    {
        std::cout << desc << "\n";
        return 1;
    }

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
    //	auto value = vm["asm"].as<std::string>();
    //	std::cerr << std::setw(24) << std::left << "Saving ASM: " << "\"" << value << "\"" <<
    //std::endl;

    PrettyPrinter pp;
    pp.setDebug(true);
    auto assembly = pp.prettyPrint(&disasm);

    std::cout << assembly << std::endl;
    //}
}
