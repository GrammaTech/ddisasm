#pragma once

#include <map>
#include <string>
#include <cstdint>
#include <vector>
#include <list>
#include <iosfwd>

#include "Table.h"
#include <boost/lexical_cast.hpp>

///
/// \class Disasm
///
/// Port of the prolog disasm.
///
class Disasm
{
public:
	struct Section
	{
		Section() = default;

		Section(const std::vector<std::string>& x)
		{
			this->Name = x[0];
			this->Size = boost::lexical_cast<uint64_t>(x[1]);
			this->StartingAddress = boost::lexical_cast<uint64_t>(x[2]);
		};

		std::string Name;
		uint64_t Size{0};
		uint64_t StartingAddress{0};
	};

	struct FunctionSymbol
	{
		FunctionSymbol() = default;

		FunctionSymbol(const std::vector<std::string>& x)
		{
			this->EA = boost::lexical_cast<uint64_t>(x[0]);
			this->Name = x[1];
		};

		std::string Name;
		uint64_t EA{0};
	};

	struct Block
	{
		Block() = default;

		// If instructions is empty, it's a NOP.
		Block(uint64_t s, uint64_t e) : StartingAddress(s), EndingAddress(e)
		{}

		// If instructions is empty, it's a NOP.
		std::vector<uint64_t> Instructions;
		uint64_t StartingAddress{0};
		uint64_t EndingAddress{0};
	};

	struct Instruction
	{
		Instruction() = default;

		Instruction(const std::vector<std::string>& x)
		{
			this->EA = boost::lexical_cast<uint64_t>(x[0]);
			this->Size = boost::lexical_cast<uint64_t>(x[1]);
			this->Opcode = x[2];
			this->Op1 = boost::lexical_cast<uint64_t>(x[3]);
			this->Op2 = boost::lexical_cast<uint64_t>(x[4]);
			this->Op3 = boost::lexical_cast<uint64_t>(x[5]);
		};

		std::string Opcode;
		uint64_t EA{0};
		uint64_t Size{0};
		uint64_t Op1{0};
		uint64_t Op2{0};
		uint64_t Op3{0};
	};

	Disasm();

	void setDebug(bool x);
	bool getDebug() const;

	///
	/// Read all of the expected file types out of a directory.
	///
	/// This calls all of the individual "parse" functions for the known file names in the given directory.
	///
	void parseDirectory(std::string x);

	///
	/// Parse the statistics facts file.
	///
	void parseSymbol(const std::string& x);
	void parseSection(const std::string& x);
	void parseRelocation(const std::string& x);
	void parseInstruction(const std::string& x);
	void parseOpRegdirect(const std::string& x);
	void parseOpImmediate(const std::string& x);
	void parseOpIndirect(const std::string& x);
	void parseDataByte(const std::string& x);

	void parseBlock(const std::string& x);
	void parseCodeInblock(const std::string& x);
	void parseRemainingEA(const std::string& x);
	void parseFunctionSymbol(const std::string& x);
	void parseMainFunction(const std::string& x);
	void parseStartFunction(const std::string& x);
	void parseFunctionEntry(const std::string& x);
	void parseAmbiguousSymbol(const std::string& x);
	void parseDirectCall(const std::string& x);
	void parsePLTReference(const std::string& x);
	void parseSymbolicOperand(const std::string& x);
	void parseMovedLabel(const std::string& x);
	void parseLabeledData(const std::string& x);
	void parseSymbolicData(const std::string& x);
	void parseSymbolMinusSymbol(const std::string& x);
	void parseMovedDataLabel(const std::string& x);
	void parseString(const std::string& x);
	void parseBSSData(const std::string& x);
	void parseStackOperand(const std::string& x);
	void parsePreferredDataAccess(const std::string& x);
	void parseDataAccessPattern(const std::string& x);
	void parseDiscardedBlock(const std::string& x);
	void parseDirectJump(const std::string& x);
	void parsePCRelativeJump(const std::string& x);
	void parsePCRelativeCall(const std::string& x);
	void parseBlockOverlap(const std::string& x);
	void parseDefUsed(const std::string& x);
	void parsePairedDataAccess(const std::string& x);
	void parseValueReg(const std::string& x);
	void parseIncompleteCFG(const std::string& x);
	void parseNoReturn(const std::string& x);
	void parseInFunction(const std::string& x);

	Table* getSymbol();
	std::vector<Section>* getSection();
	Table* getRelocation();
	std::vector<Instruction>* getInstruction();
	Table* getOPRegdirect();
	Table* getOPImmediate();
	Table* getOPIndirect();
	Table* getDataByte();
	Table* getBlock();
	Table* getCodeInBlock();
	std::vector<uint64_t>* getRemainingEA();
	std::vector<FunctionSymbol>* getFunctionSymbol();
	std::vector<uint64_t>* getMainFunction();
	std::vector<uint64_t>* getStartFunction();
	std::vector<uint64_t>* getFunctionEntry();
	Table* getAmbiguousSymbol();
	Table* getDirectCall();
	Table* getPLTReference();
	Table* getSymbolicOperand();
	Table* getMovedLabel();
	Table* getLabeledData();
	Table* getSymbolicData();
	Table* getSymbolMinusSymbol();
	Table* getMovedDataLabel();
	Table* getString();
	Table* getBSSData();
	Table* getStackOperand();
	Table* getPreferredDataAccess();
	Table* getDataAccessPattern();
	Table* getDiscardedBlock();
	Table* getDirectJump();
	Table* getPCRelativeJump();
	Table* getPCRelativeCall();
	Table* getBlockOverlap();
	Table* getDefUsed();
	Table* getPairedDataAccess();
	Table* getValueReg();
	Table* getIncompleteCFG();
	Table* getNoReturn();
	Table* getInFunction();

	///
	/// Pretty print to the given file name
	///
	void prettyPrint(std::string x) const;

protected:
	void printHeader(std::ofstream& ofs) const;

	std::list<Block> getCodeBlocks() const;
	void adjustPadding(std::list<Disasm::Block>& blocks) const;

	void printBlock(std::ofstream& ofs, const Block& x) const;

	bool skipEA(const uint64_t x) const;
	void condPrintSectionHeader(std::ofstream& ofs, const Block& x) const;

	void printSectionHeader(std::ofstream& ofs, const std::string& x) const;

	std::string getSectionName(uint64_t x) const;

	void printBar(std::ofstream& ofs) const;
	void printFunctionHeader(std::ofstream& ofs, uint64_t ea) const;
	void printLabel(std::ofstream& ofs, uint64_t ea) const;
	void printInstruction(std::ofstream& ofs, uint64_t ea) const;
	void printInstructionNop(std::ofstream& ofs) const;
	void printEA(std::ofstream& ofs, uint64_t ea) const;
	void condPrintGlobalSymbol(std::ofstream& ofs, uint64_t ea) const;
	std::string getFunctionName(uint64_t x) const;
	std::string getGlobalSymbolName(uint64_t ea) const;
	std::string cleanSymbolNameSuffix(std::string x) const;

	Instruction getInstructionAt(uint64_t ea) const;
	std::string adaptOpcode(const std::string& x) const;

private:
	// these are facts generated by the decoder
	Table symbol{5};
	std::vector<Section> section;
	Table relocation{4};
	std::vector<Instruction> instruction;
	Table op_regdirect{2};
	Table op_immediate{2};
	Table op_indirect{7};
	Table data_byte{2};

	// these facts are necessary for printing the asm
	Table block{1};
	Table code_in_block{2};
	std::vector<uint64_t> remaining_ea{1};
	std::vector<FunctionSymbol> function_symbol{2};
	std::vector<uint64_t> main_function{1};
	std::vector<uint64_t> start_function{1};
	std::vector<uint64_t> function_entry{1};
	Table ambiguous_symbol{1};
	Table direct_call{2};
	Table plt_reference{2};
	Table symbolic_operand{2};
	Table moved_label{4};
	Table labeled_data{1};
	Table symbolic_data{2};
	Table symbol_minus_symbol{3};
	Table moved_data_label{3};
	Table string{2};
	Table bss_data{1};

	// these facts are only used for generating hints
	Table stack_operand{2};
	Table preferred_data_access{2};
	Table data_access_pattern{4};

	// these facts are only collected for printing debugging information
	Table discarded_block{1};
	Table direct_jump{2};
	Table pc_relative_jump{2};
	Table pc_relative_call{2};
	Table block_overlap{2};
	Table def_used{4};
	Table paired_data_access{6};
	Table value_reg{7};
	Table incomplete_cfg{1};
	Table no_return{1};
	Table in_function{2};

	// Stores section names.
	std::vector<std::string> asm_skip_section;
	std::vector<std::string> asm_skip_function;

	bool debug{false};
};
