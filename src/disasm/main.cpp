#include "disasm.h"
#include <iostream>
#include <boost/program_options.hpp>

int main(int argc, char** argv)
{
	boost::program_options::options_description desc("Allowed options");
	desc.add_options()
    	("help", "Produce help message.")
    	("directory", boost::program_options::value<std::string>(), "Set the directory to parse.");

	boost::program_options::variables_map vm;
	boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc), vm);
	boost::program_options::notify(vm);    

	if(vm.count("help") || argc < 2) 
	{
    	std::cout << desc << "\n";
    	return 1;
	}

	std::string directory;
	if(vm.count("directory")) 
	{
    	directory = vm["directory"].as<std::string>();
	} 

	Disasm disasm;
	disasm.parseDirectory(directory);
}
