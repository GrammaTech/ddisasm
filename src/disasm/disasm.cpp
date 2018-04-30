#include "disasm.h"
#include <iostream>
#include <boost/algorithm/string/trim.hpp>

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
	this->section.parseFile(x);
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
	std::cerr << " # Number of op_immeiate: " << this->op_immediate.size() << std::endl;
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
	std::cerr << " # number of block: " << this->block.size() << std::endl;
}

void Disasm::parseCodeInblock(const std::string& x)
{
	this->code_in_block.parseFile(x);
	std::cerr << " # number of code_in_block: " << this->code_in_block.size() << std::endl;
}

void Disasm::parseRemainingEA(const std::string& x)
{
	this->remaining_ea.parseFile(x);
	std::cerr << " # number of remaining_ea: " << this->remaining_ea.size() << std::endl;
}

void Disasm::parseFunctionSymbol(const std::string& x)
{
	this->function_symbol.parseFile(x);
	std::cerr << " # number of function_symbol: " << this->function_symbol.size() << std::endl;
}

void Disasm::parseMainFunction(const std::string& x)
{
	this->main_function.parseFile(x);
	std::cerr << " # number of main_function: " << this->main_function.size() << std::endl;
}

void Disasm::parseStartFunction(const std::string& x)
{
	this->start_function.parseFile(x);
	std::cerr << " # number of start_function: " << this->start_function.size() << std::endl;
}

void Disasm::parseFunctionEntry(const std::string& x)
{
	this->function_entry.parseFile(x);
	std::cerr << " # number of function_entry: " << this->function_entry.size() << std::endl;
}

void Disasm::parseAmbiguousSymbol(const std::string& x)
{
	this->ambiguous_symbol.parseFile(x);
	std::cerr << " # number of ambiguous_symbol: " << this->ambiguous_symbol.size() << std::endl;
}

void Disasm::parseDirectCall(const std::string& x)
{
	this->direct_call.parseFile(x);
	std::cerr << " # number of direct_call: " << this->direct_call.size() << std::endl;
}

void Disasm::parsePLTReference(const std::string& x)
{
	this->plt_reference.parseFile(x);
	std::cerr << " # number of plt_reference: " << this->plt_reference.size() << std::endl;
}

void Disasm::parseSymbolicOperand(const std::string& x)
{
	this->symbolic_operand.parseFile(x);
	std::cerr << " # number of symbolic_operand: " << this->symbolic_operand.size() << std::endl;
}

void Disasm::parseMovedLabel(const std::string& x)
{
	this->moved_label.parseFile(x);
	std::cerr << " # number of moved_label: " << this->moved_label.size() << std::endl;
}

void Disasm::parseLabeledData(const std::string& x)
{
	this->labeled_data.parseFile(x);
	std::cerr << " # number of labeled_data: " << this->labeled_data.size() << std::endl;
}

void Disasm::parseSymbolicData(const std::string& x)
{
	this->symbolic_data.parseFile(x);
	std::cerr << " # number of symbolic_data: " << this->symbolic_data.size() << std::endl;
}

void Disasm::parseSymbolMinusSymbol(const std::string& x)
{
	this->symbol_minus_symbol.parseFile(x);
	std::cerr << " # number of symbol_minus_symbol: " << this->symbol_minus_symbol.size() << std::endl;
}

void Disasm::parseMovedDataLabel(const std::string& x)
{
	this->moved_data_label.parseFile(x);
	std::cerr << " # number of moved_data_label: " << this->moved_data_label.size() << std::endl;
}

void Disasm::parseString(const std::string& x)
{
	this->string.parseFile(x);
	std::cerr << " # number of string: " << this->string.size() << std::endl;
}

void Disasm::parseBSSData(const std::string& x)
{
	this->bss_data.parseFile(x);
	std::cerr << " # number of bss_data: " << this->bss_data.size() << std::endl;
}

void Disasm::parseStackOperand(const std::string& x)
{
	this->stack_operand.parseFile(x);
	std::cerr << " # number of stack_operand: " << this->stack_operand.size() << std::endl;
}

void Disasm::parsePreferredDataAccess(const std::string& x)
{
	this->preferred_data_access.parseFile(x);
	std::cerr << " # number of preferred_data_access: " << this->preferred_data_access.size() << std::endl;
}

void Disasm::parseDataAccessPattern(const std::string& x)
{
	this->data_access_pattern.parseFile(x);
	std::cerr << " # number of data_access_pattern: " << this->data_access_pattern.size() << std::endl;
}

void Disasm::parseDiscardedBlock(const std::string& x)
{
	this->discarded_block.parseFile(x);
	std::cerr << " # number of discarded_block: " << this->discarded_block.size() << std::endl;
}

void Disasm::parseDirectJump(const std::string& x)
{
	this->direct_jump.parseFile(x);
	std::cerr << " # number of direct_jump: " << this->direct_jump.size() << std::endl;
}

void Disasm::parsePCRelativeJump(const std::string& x)
{
	this->pc_relative_jump.parseFile(x);
	std::cerr << " # number of pc_relative_jump: " << this->pc_relative_jump.size() << std::endl;
}

void Disasm::parsePCRelativeCall(const std::string& x)
{
	this->pc_relative_call.parseFile(x);
	std::cerr << " # number of pc_relative_call: " << this->pc_relative_call.size() << std::endl;
}

void Disasm::parseBlockOverlap(const std::string& x)
{
	this->block_overlap.parseFile(x);
	std::cerr << " # number of block_overlap: " << this->block_overlap.size() << std::endl;
}

void Disasm::parseDefUsed(const std::string& x)
{
	this->def_used.parseFile(x);
	std::cerr << " # number of def_used: " << this->def_used.size() << std::endl;
}

void Disasm::parsePairedDataAccess(const std::string& x)
{
	this->paired_data_access.parseFile(x);
	std::cerr << " # number of paired_data_access: " << this->paired_data_access.size() << std::endl;
}

void Disasm::parseValueReg(const std::string& x)
{
	this->value_reg.parseFile(x);
	std::cerr << " # number of value_reg: " << this->value_reg.size() << std::endl;
}

void Disasm::parseIncompleteCFG(const std::string& x)
{
	this->incomplete_cfg.parseFile(x);
	std::cerr << " # number of incomplete_cfg: " << this->incomplete_cfg.size() << std::endl;
}

void Disasm::parseNoReturn(const std::string& x)
{
	this->no_return.parseFile(x);
	std::cerr << " # number of no_return: " << this->no_return.size() << std::endl;
}

void Disasm::parseInFunction(const std::string& x)
{
	this->in_function.parseFile(x);
	std::cerr << " # number of in_function: " << this->in_function.size() << std::endl;
}
