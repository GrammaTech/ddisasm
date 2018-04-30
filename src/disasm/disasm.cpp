#include "disasm.h"
#include <iostream>
#include <fstream>
#include <boost/algorithm/string/trim.hpp>
#include <boost/lexical_cast.hpp>

Disasm::Disasm()
{
	this->asm_skip_section = {".comment", ".plt", ".init", ".fini", ".got", ".plt.got", ".got.plt"};
	this->asm_skip_function = {"_start", "deregister_tm_clone", "register_tm_clone", "__do_global_dtors_au", "frame_dumm", "__libc_csu_fin", "__libc_csu_ini" };
}

void Disasm::setDebug(bool x)
{
	this->debug = x;
}

bool Disasm::getDebug() const
{
	return this->debug;
}

void Disasm::parseDirectory(std::string x)
{
	boost::trim(x);

	this->parseSymbol(x + "/symbol.facts");
	this->parseSection(x + "/section.facts");
	this->parseRelocation(x + "/relocation.facts");
	this->parseInstruction(x + "/instruction.facts");
	this->parseOpRegdirect(x + "/op_regdirect.facts");
	this->parseOpImmediate(x + "/op_immediate.facts");
	this->parseOpIndirect(x + "/op_indirect.facts");
	this->parseDataByte(x + "/data_byte.facts");

	this->parseBlock(x + "/block.csv");
	this->parseCodeInblock(x + "/code_in_block.csv");
	this->parseRemainingEA(x + "/phase2-remaining_ea.csv");
	this->parseFunctionSymbol(x + "/function_symbol.csv");
	this->parseMainFunction(x + "/main_function.csv");
	this->parseStartFunction(x + "/start_function.csv");
	this->parseFunctionEntry(x + "/function_entry2.csv");
	this->parseAmbiguousSymbol(x + "/ambiguous_symbol.csv");
	this->parseDirectCall(x + "/direct_call.csv");
	this->parsePLTReference(x + "/plt_reference.csv");
	this->parseSymbolicOperand(x + "/symbolic_operand.csv");
	this->parseMovedLabel(x + "/moved_label.csv");
	this->parseLabeledData(x + "/labeled_data.csv");
	this->parseSymbolicData(x + "/symbolic_data.csv");
	this->parseSymbolMinusSymbol(x + "/symbol_minus_symbol.csv");
	this->parseMovedDataLabel(x + "/moved_data_label.csv");
	this->parseString(x + "/string.csv");
	this->parseBSSData(x + "/bss_data.csv");

	this->parseStackOperand(x + "/stack_operand.csv");
	this->parsePreferredDataAccess(x + "/preferred_data_access.csv");
	this->parseDataAccessPattern(x + "/data_access_pattern.csv");

	this->parseDiscardedBlock(x + "/discarded_block.csv");
	this->parseDirectJump(x + "/direct_jump.csv");
	this->parsePCRelativeJump(x + "/pc_relative_jump.csv");
	this->parsePCRelativeCall(x + "/pc_relative_call.csv");
	this->parseBlockOverlap(x + "/block_still_overlap.csv");
	this->parseDefUsed(x + "/def_used.csv");
	
	this->parsePairedDataAccess(x + "/paired_data_access.csv");
	this->parseValueReg(x + "/value_reg.csv");
	this->parseIncompleteCFG(x + "/incomplete_cfg.csv");
	this->parseNoReturn(x + "/no_return.csv");
	this->parseInFunction(x + "/in_function.csv");
}

void Disasm::parseSymbol(const std::string& x)
{
	this->symbol.parseFile(x);
	std::cerr << " # Number of symbol: " << this->symbol.size() << std::endl;
}

void Disasm::parseSection(const std::string& x)
{
	Table fromFile{3};
	fromFile.parseFile(x);

	for(const auto& ff : fromFile)
	{
		this->section.push_back(Disasm::Section(ff));
	}

	std::cerr << " # Number of section: " << this->section.size() << std::endl;
}

void Disasm::parseRelocation(const std::string& x)
{
	this->relocation.parseFile(x);
	std::cerr << " # Number of relocation: " << this->relocation.size() << std::endl;
}

void Disasm::parseInstruction(const std::string& x)
{
	this->instruction.parseFile(x);
	std::cerr << " # Number of instruction: " << this->instruction.size() << std::endl;
}

void Disasm::parseOpRegdirect(const std::string& x)
{
	this->op_regdirect.parseFile(x);
	std::cerr << " # Number of op_regdirect: " << this->op_regdirect.size() << std::endl;
}

void Disasm::parseOpImmediate(const std::string& x)
{
	this->op_immediate.parseFile(x);
	std::cerr << " # Number of op_immediate: " << this->op_immediate.size() << std::endl;
}

void Disasm::parseOpIndirect(const std::string& x)
{
	this->op_indirect.parseFile(x);
	std::cerr << " # Number of op_indirect: " << this->op_indirect.size() << std::endl;
}

void Disasm::parseDataByte(const std::string& x)
{
	this->data_byte.parseFile(x);
	std::cerr << " # Number of data_byte: " << this->data_byte.size() << std::endl;
}

void Disasm::parseBlock(const std::string& x)
{
	this->block.parseFile(x);
	std::cerr << " # Number of block: " << this->block.size() << std::endl;
}

void Disasm::parseCodeInblock(const std::string& x)
{
	this->code_in_block.parseFile(x);
	std::cerr << " # Number of code_in_block: " << this->code_in_block.size() << std::endl;
}

void Disasm::parseRemainingEA(const std::string& x)
{
	Table fromFile{1};
	fromFile.parseFile(x);

	for(const auto& ff : fromFile)
	{
		this->remaining_ea.push_back(boost::lexical_cast<uint64_t>(ff[0]));
	}

	std::cerr << " # Number of remaining_ea: " << this->remaining_ea.size() << std::endl;
}

void Disasm::parseFunctionSymbol(const std::string& x)
{
	Table fromFile{2};
	fromFile.parseFile(x);

	for(const auto& ff : fromFile)
	{
		this->function_symbol.push_back(Disasm::FunctionSymbol(ff));
	}

	std::cerr << " # Number of function_symbol: " << this->function_symbol.size() << std::endl;
}

void Disasm::parseMainFunction(const std::string& x)
{
	Table fromFile{1};
	fromFile.parseFile(x);

	for(const auto& ff : fromFile)
	{
		this->main_function.push_back(boost::lexical_cast<uint64_t>(ff[0]));
	}

	std::cerr << " # Number of main_function: " << this->main_function.size() << std::endl;
}

void Disasm::parseStartFunction(const std::string& x)
{
	Table fromFile{1};
	fromFile.parseFile(x);

	for(const auto& ff : fromFile)
	{
		this->start_function.push_back(boost::lexical_cast<uint64_t>(ff[0]));
	}

	std::cerr << " # Number of start_function: " << this->start_function.size() << std::endl;
}

void Disasm::parseFunctionEntry(const std::string& x)
{
	Table fromFile{1};
	fromFile.parseFile(x);

	for(const auto& ff : fromFile)
	{
		this->function_entry.push_back(boost::lexical_cast<uint64_t>(ff[0]));
	}

	std::sort(std::begin(this->function_entry), std::end(this->function_entry));
	
	std::cerr << " # Number of function_entry: " << this->function_entry.size() << std::endl;
}

void Disasm::parseAmbiguousSymbol(const std::string& x)
{
	this->ambiguous_symbol.parseFile(x);
	std::cerr << " # Number of ambiguous_symbol: " << this->ambiguous_symbol.size() << std::endl;
}

void Disasm::parseDirectCall(const std::string& x)
{
	this->direct_call.parseFile(x);
	std::cerr << " # Number of direct_call: " << this->direct_call.size() << std::endl;
}

void Disasm::parsePLTReference(const std::string& x)
{
	this->plt_reference.parseFile(x);
	std::cerr << " # Number of plt_reference: " << this->plt_reference.size() << std::endl;
}

void Disasm::parseSymbolicOperand(const std::string& x)
{
	this->symbolic_operand.parseFile(x);
	std::cerr << " # Number of symbolic_operand: " << this->symbolic_operand.size() << std::endl;
}

void Disasm::parseMovedLabel(const std::string& x)
{
	this->moved_label.parseFile(x);
	std::cerr << " # Number of moved_label: " << this->moved_label.size() << std::endl;
}

void Disasm::parseLabeledData(const std::string& x)
{
	this->labeled_data.parseFile(x);
	std::cerr << " # Number of labeled_data: " << this->labeled_data.size() << std::endl;
}

void Disasm::parseSymbolicData(const std::string& x)
{
	this->symbolic_data.parseFile(x);
	std::cerr << " # Number of symbolic_data: " << this->symbolic_data.size() << std::endl;
}

void Disasm::parseSymbolMinusSymbol(const std::string& x)
{
	this->symbol_minus_symbol.parseFile(x);
	std::cerr << " # Number of symbol_minus_symbol: " << this->symbol_minus_symbol.size() << std::endl;
}

void Disasm::parseMovedDataLabel(const std::string& x)
{
	this->moved_data_label.parseFile(x);
	std::cerr << " # Number of moved_data_label: " << this->moved_data_label.size() << std::endl;
}

void Disasm::parseString(const std::string& x)
{
	this->string.parseFile(x);
	std::cerr << " # Number of string: " << this->string.size() << std::endl;
}

void Disasm::parseBSSData(const std::string& x)
{
	this->bss_data.parseFile(x);
	std::cerr << " # Number of bss_data: " << this->bss_data.size() << std::endl;
}

void Disasm::parseStackOperand(const std::string& x)
{
	this->stack_operand.parseFile(x);
	std::cerr << " # Number of stack_operand: " << this->stack_operand.size() << std::endl;
}

void Disasm::parsePreferredDataAccess(const std::string& x)
{
	this->preferred_data_access.parseFile(x);
	std::cerr << " # Number of preferred_data_access: " << this->preferred_data_access.size() << std::endl;
}

void Disasm::parseDataAccessPattern(const std::string& x)
{
	this->data_access_pattern.parseFile(x);
	std::cerr << " # Number of data_access_pattern: " << this->data_access_pattern.size() << std::endl;
}

void Disasm::parseDiscardedBlock(const std::string& x)
{
	this->discarded_block.parseFile(x);
	std::cerr << " # Number of discarded_block: " << this->discarded_block.size() << std::endl;
}

void Disasm::parseDirectJump(const std::string& x)
{
	this->direct_jump.parseFile(x);
	std::cerr << " # Number of direct_jump: " << this->direct_jump.size() << std::endl;
}

void Disasm::parsePCRelativeJump(const std::string& x)
{
	this->pc_relative_jump.parseFile(x);
	std::cerr << " # Number of pc_relative_jump: " << this->pc_relative_jump.size() << std::endl;
}

void Disasm::parsePCRelativeCall(const std::string& x)
{
	this->pc_relative_call.parseFile(x);
	std::cerr << " # Number of pc_relative_call: " << this->pc_relative_call.size() << std::endl;
}

void Disasm::parseBlockOverlap(const std::string& x)
{
	this->block_overlap.parseFile(x);
	std::cerr << " # Number of block_overlap: " << this->block_overlap.size() << std::endl;
}

void Disasm::parseDefUsed(const std::string& x)
{
	this->def_used.parseFile(x);
	std::cerr << " # Number of def_used: " << this->def_used.size() << std::endl;
}

void Disasm::parsePairedDataAccess(const std::string& x)
{
	this->paired_data_access.parseFile(x);
	std::cerr << " # Number of paired_data_access: " << this->paired_data_access.size() << std::endl;
}

void Disasm::parseValueReg(const std::string& x)
{
	this->value_reg.parseFile(x);
	std::cerr << " # Number of value_reg: " << this->value_reg.size() << std::endl;
}

void Disasm::parseIncompleteCFG(const std::string& x)
{
	this->incomplete_cfg.parseFile(x);
	std::cerr << " # Number of incomplete_cfg: " << this->incomplete_cfg.size() << std::endl;
}

void Disasm::parseNoReturn(const std::string& x)
{
	this->no_return.parseFile(x);
	std::cerr << " # Number of no_return: " << this->no_return.size() << std::endl;
}

void Disasm::parseInFunction(const std::string& x)
{
	this->in_function.parseFile(x);
	std::cerr << " # Number of in_function: " << this->in_function.size() << std::endl;
}

Table* Disasm::getSymbol()
{
	return &this->symbol;
}

std::vector<Disasm::Section>* Disasm::getSection()
{
	return &this->section;
}

Table* Disasm::getRelocation()
{
	return &this->relocation;
}

Table* Disasm::getInstruction()
{
	return &this->instruction;
}

Table* Disasm::getOPRegdirect()
{
	return &this->op_regdirect;
}

Table* Disasm::getOPImmediate()
{
	return &this->op_immediate;
}

Table* Disasm::getOPIndirect()
{
	return &this->op_indirect;
}

Table* Disasm::getDataByte()
{
	return &this->data_byte;
}

Table* Disasm::getBlock()
{
	return &this->block;
}

Table* Disasm::getCodeInBlock()
{
	return &this->code_in_block;
}

std::vector<uint64_t>* Disasm::getRemainingEA()
{
	return &this->remaining_ea;
}

std::vector<Disasm::FunctionSymbol>* Disasm::getFunctionSymbol()
{
	return &this->function_symbol;
}

std::vector<uint64_t>* Disasm::getMainFunction()
{
	return &this->main_function;
}

std::vector<uint64_t>* Disasm::getStartFunction()
{
	return &this->start_function;
}

std::vector<uint64_t>* Disasm::getFunctionEntry()
{
	return &this->function_entry;
}

Table* Disasm::getAmbiguousSymbol()
{
	return &this->ambiguous_symbol;
}

Table* Disasm::getDirectCall()
{
	return &this->direct_call;
}

Table* Disasm::getPLTReference()
{
	return &this->plt_reference;
}

Table* Disasm::getSymbolicOperand()
{
	return &this->symbolic_operand;
}

Table* Disasm::getMovedLabel()
{
	return &this->moved_label;
}

Table* Disasm::getLabeledData()
{
	return &this->labeled_data;
}

Table* Disasm::getSymbolicData()
{
	return &this->symbolic_data;
}

Table* Disasm::getSymbolMinusSymbol()
{
	return &this->symbol_minus_symbol;
}

Table* Disasm::getMovedDataLabel()
{
	return &this->moved_data_label;
}

Table* Disasm::getString()
{
	return &this->string;
}

Table* Disasm::getBSSData()
{
	return &this->bss_data;
}

Table* Disasm::getStackOperand()
{
	return &this->stack_operand;
}

Table* Disasm::getPreferredDataAccess()
{
	return &this->preferred_data_access;
}

Table* Disasm::getDataAccessPattern()
{
	return &this->data_access_pattern;
}

Table* Disasm::getDiscardedBlock()
{
	return &this->discarded_block;
}

Table* Disasm::getDirectJump()
{
	return &this->direct_jump;
}

Table* Disasm::getPCRelativeJump()
{
	return &this->pc_relative_jump;
}

Table* Disasm::getPCRelativeCall()
{
	return &this->pc_relative_call;
}

Table* Disasm::getBlockOverlap()
{
	return &this->block_overlap;
}

Table* Disasm::getDefUsed()
{
	return &this->def_used;
}

Table* Disasm::getPairedDataAccess()
{
	return &this->paired_data_access;
}

Table* Disasm::getValueReg()
{
	return &this->value_reg;
}

Table* Disasm::getIncompleteCFG()
{
	return &this->incomplete_cfg;
}

Table* Disasm::getNoReturn()
{
	return &this->no_return;
}

Table* Disasm::getInFunction()
{
	return &this->in_function;
}

void Disasm::prettyPrint(std::string x) const
{
	std::ofstream ofs;
	ofs.open(x);

	if(ofs.is_open() == true)
	{
		this->printHeader(ofs);
	}

	const auto blocks = this->getCodeBlocks();
	for(const auto& b : blocks)
	{
		this->printBlock(ofs, b);
	}
}

void Disasm::printHeader(std::ofstream& ofs) const
{
	ofs << "#===================================" << std::endl;
	ofs << ".intel_syntax noprefix" << std::endl;
	ofs << "#=================================== " << std::endl;
	ofs << "" << std::endl;
	ofs << "nop" << std::endl;
	ofs << "nop" << std::endl;
	ofs << "nop" << std::endl;
	ofs << "nop" << std::endl;
	ofs << "nop" << std::endl;
	ofs << "nop" << std::endl;
	ofs << "nop" << std::endl;
	ofs << "nop" << std::endl;
}

std::list<Disasm::Block> Disasm::getCodeBlocks() const
{
	std::list<Disasm::Block> blocks;

	for(auto& i : this->block)
	{
		Disasm::Block b;

		for(auto& cib : this->code_in_block)
		{
			// The instruction's block address == the block's addres.
			if(cib[1] == i[0])
			{
				// Push back the instruction.
				b.Instructions.push_back(boost::lexical_cast<uint64_t>(cib[0]));
			}
		}

		std::sort(std::begin(b.Instructions), std::end(b.Instructions));

		b.StartingAddress = boost::lexical_cast<uint64_t>(i[0]);

		const auto address = *std::rbegin(b.Instructions);
		b.EndingAddress = address + boost::lexical_cast<uint64_t>(this->instruction.getRow(boost::lexical_cast<std::string>(address))[1]);

		blocks.push_back(std::move(b));
	}

	blocks.sort([](const auto& left, const auto& right)
		{
			return left.StartingAddress < right.StartingAddress;
		});

	if(this->getDebug() == false)
	{
		this->adjustPadding(blocks);
	}

	return blocks;
}

void Disasm::adjustPadding(std::list<Disasm::Block>& blocks) const
{
	for(auto i = std::begin(blocks); i != std::end(blocks); ++i)
	{
		auto next = i;
		++next;

		const auto gap = next->StartingAddress - i->EndingAddress;

		// If we have overlap, erase the next element in the list.
		if(i->EndingAddress > next->StartingAddress)
		{
			blocks.erase(next);
		}
		else if(gap > 0)
		{
			// insert a block with no instructions.
			// This should be interpreted as nop's.
			blocks.insert(next, Block{i->EndingAddress, next->StartingAddress});
		}
	}
}

void Disasm::printBlock(std::ofstream& ofs, const Block& x) const
{
	if(this->skipEA(x.StartingAddress) == false)
	{
		this->condPrintSectionHeader(ofs, x);
	}
}

void Disasm::condPrintSectionHeader(std::ofstream& ofs, const Block& x) const
{
	for(const auto& s : this->section)
	{
		if(s.StartingAddress == x.StartingAddress)
		{
			this->printSectionHeader(ofs, s.Name);
			return;
		}
	}
}

void Disasm::printSectionHeader(std::ofstream& ofs, const std::string& x) const
{
	ofs << "\n\n#=================================== \n";

	if(x == ".text")
	{
	    ofs << ".text\n";
	}
	else
	{
    	ofs << ".section " << x << "\n";
    }

    ofs << "#=================================== \n\n";
}

bool Disasm::skipEA(const uint64_t x) const
{
	for(const auto& s : this->section)
	{
		//std::cout << "Searching " << s.Name << "\n";
		const auto found = std::find(std::begin(this->asm_skip_section), std::end(this->asm_skip_section), s.Name);

		if(found != std::end(this->asm_skip_section))
		{
			//std::cout << "Found " << s.Name << ": " << "((" << x << " >= " << s.StartingAddress << ") && (" << x  << " < (" << s.StartingAddress << " + " << s.Size << ")))" << "\n";
			const auto isSkipped = ((x >= s.StartingAddress) && (x < (s.StartingAddress + s.Size)));

			if(isSkipped == true)
			{
				std::cout << "Skipping " << s.Name << "\n";
				return true;
			}
		}
	}

	uint64_t xFunctionAddress{0};

	for(auto fe = std::begin(this->function_entry); fe != std::end(this->function_entry); ++fe)
	{
		auto feNext = fe;
		feNext++;

		if(x >= *fe && x < *feNext)
		{
			xFunctionAddress = *fe;
			continue;
		}
	}

	std::string xFunctionName{};

	for(auto& fs : this->function_symbol)
	{
		if(fs.EA == xFunctionAddress)
		{
			xFunctionName = fs.Name;
			continue;
		}
	}

	// if we have a function address.
	// and that funciton address has a name.
	// is that name in our skip list?

	if(xFunctionName.empty() == false)
	{
		const auto found = std::find(std::begin(this->asm_skip_function), std::end(this->asm_skip_function), xFunctionName);
		return found != std::end(this->asm_skip_function);
	}

	return false;
}

std::string Disasm::getSectionName(uint64_t x) const
{
	for(auto& s : this->section)
	{
		if(s.StartingAddress == x)
		{
			return s.Name;
		}
	}

	return std::string{};
}
