#include "DisasmData.h"
#include <boost/algorithm/string/trim.hpp>
#include <boost/lexical_cast.hpp>
#include <fstream>
#include <iostream>

void DisasmData::parseDirectory(std::string x)
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

void DisasmData::parseSymbol(const std::string& x)
{
    Table fromFile{5};
    fromFile.parseFile(x);

    for(const auto& ff : fromFile)
    {
        this->symbol.push_back(Symbol(ff));
    }

    std::cerr << " # Number of symbol: " << this->symbol.size() << std::endl;
}

void DisasmData::parseSection(const std::string& x)
{
    Table fromFile{3};
    fromFile.parseFile(x);

    for(const auto& ff : fromFile)
    {
        this->section.push_back(Section(ff));
    }

    std::cerr << " # Number of section: " << this->section.size() << std::endl;
}

void DisasmData::parseRelocation(const std::string& x)
{
    Table fromFile{5};
    fromFile.parseFile(x);

    for(const auto& ff : fromFile)
    {
        this->relocation.push_back(Relocation(ff));
    }

    std::cerr << " # Number of relocation: " << this->relocation.size() << std::endl;
}

void DisasmData::parseInstruction(const std::string& x)
{
    Table fromFile{6};
    fromFile.parseFile(x);

    for(const auto& ff : fromFile)
    {
        this->instruction.push_back(Instruction(ff));
    }

    std::cerr << " # Number of instruction: " << this->instruction.size() << std::endl;
}

void DisasmData::parseOpRegdirect(const std::string& x)
{
    Table fromFile{2};
    fromFile.parseFile(x);

    for(const auto& ff : fromFile)
    {
        this->op_regdirect.push_back(OpRegdirect(ff));
    }

    std::cerr << " # Number of op_regdirect: " << this->op_regdirect.size() << std::endl;
}

void DisasmData::parseOpImmediate(const std::string& x)
{
    Table fromFile{2};
    fromFile.parseFile(x);

    for(const auto& ff : fromFile)
    {
        this->op_immediate.push_back(OpImmediate(ff));
    }

    std::cerr << " # Number of op_immediate: " << this->op_immediate.size() << std::endl;
}

void DisasmData::parseOpIndirect(const std::string& x)
{
    Table fromFile{7};
    fromFile.parseFile(x);

    for(const auto& ff : fromFile)
    {
        this->op_indirect.push_back(OpIndirect(ff));
    }

    std::cerr << " # Number of op_indirect: " << this->op_indirect.size() << std::endl;
}

void DisasmData::parseDataByte(const std::string& x)
{
    Table fromFile{2};
    fromFile.parseFile(x);

    for(const auto& ff : fromFile)
    {
        this->data_byte.push_back(DataByte(ff));
    }

    std::cerr << " # Number of data_byte: " << this->data_byte.size() << std::endl;
}

void DisasmData::parseBlock(const std::string& x)
{
    Table fromFile{1};
    fromFile.parseFile(x);

    for(const auto& ff : fromFile)
    {
        this->block.push_back(boost::lexical_cast<uint64_t>(ff[0]));
    }

    std::cerr << " # Number of block: " << this->block.size() << std::endl;
}

void DisasmData::parseCodeInblock(const std::string& x)
{
    Table fromFile{2};
    fromFile.parseFile(x);

    for(const auto& ff : fromFile)
    {
        this->code_in_block.push_back(CodeInBlock(ff));
    }

    std::cerr << " # Number of code_in_block: " << this->code_in_block.size() << std::endl;
}

void DisasmData::parseRemainingEA(const std::string& x)
{
    Table fromFile{1};
    fromFile.parseFile(x);

    for(const auto& ff : fromFile)
    {
        this->remaining_ea.push_back(boost::lexical_cast<uint64_t>(ff[0]));
    }

    std::cerr << " # Number of remaining_ea: " << this->remaining_ea.size() << std::endl;
}

void DisasmData::parseFunctionSymbol(const std::string& x)
{
    Table fromFile{2};
    fromFile.parseFile(x);

    for(const auto& ff : fromFile)
    {
        this->function_symbol.push_back(FunctionSymbol(ff));
    }

    std::cerr << " # Number of function_symbol: " << this->function_symbol.size() << std::endl;
}

void DisasmData::parseMainFunction(const std::string& x)
{
    Table fromFile{1};
    fromFile.parseFile(x);

    for(const auto& ff : fromFile)
    {
        this->main_function.push_back(boost::lexical_cast<uint64_t>(ff[0]));
    }

    std::cerr << " # Number of main_function: " << this->main_function.size() << std::endl;
}

void DisasmData::parseStartFunction(const std::string& x)
{
    Table fromFile{1};
    fromFile.parseFile(x);

    for(const auto& ff : fromFile)
    {
        this->start_function.push_back(boost::lexical_cast<uint64_t>(ff[0]));
    }

    std::cerr << " # Number of start_function: " << this->start_function.size() << std::endl;
}

void DisasmData::parseFunctionEntry(const std::string& x)
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

void DisasmData::parseAmbiguousSymbol(const std::string& x)
{
    Table fromFile{1};
    fromFile.parseFile(x);

    for(const auto& ff : fromFile)
    {
        this->ambiguous_symbol.push_back(boost::lexical_cast<uint64_t>(ff[0]));
    }

    std::cerr << " # Number of ambiguous_symbol: " << this->ambiguous_symbol.size() << std::endl;
}

void DisasmData::parseDirectCall(const std::string& x)
{
    Table fromFile{2};
    fromFile.parseFile(x);

    for(const auto& ff : fromFile)
    {
        this->direct_call.push_back(DirectCall(ff));
    }

    std::cerr << " # Number of direct_call: " << this->direct_call.size() << std::endl;
}

void DisasmData::parsePLTReference(const std::string& x)
{
    Table fromFile{2};
    fromFile.parseFile(x);

    for(const auto& ff : fromFile)
    {
        this->plt_reference.push_back(PLTReference(ff));
    }

    std::cerr << " # Number of plt_reference: " << this->plt_reference.size() << std::endl;
}

void DisasmData::parseSymbolicOperand(const std::string& x)
{
    Table fromFile{2};
    fromFile.parseFile(x);

    for(const auto& ff : fromFile)
    {
        this->symbolic_operand.push_back(SymbolicOperand(ff));
    }

    std::cerr << " # Number of symbolic_operand: " << this->symbolic_operand.size() << std::endl;
}

void DisasmData::parseMovedLabel(const std::string& x)
{
    Table fromFile{4};
    fromFile.parseFile(x);

    for(const auto& ff : fromFile)
    {
        this->moved_label.push_back(MovedLabel(ff));
    }

    std::cerr << " # Number of moved_label: " << this->moved_label.size() << std::endl;
}

void DisasmData::parseLabeledData(const std::string& x)
{
    Table fromFile{1};
    fromFile.parseFile(x);

    for(const auto& ff : fromFile)
    {
        this->labeled_data.push_back(boost::lexical_cast<uint64_t>(ff[0]));
    }

    std::cerr << " # Number of labeled_data: " << this->labeled_data.size() << std::endl;
}

void DisasmData::parseSymbolicData(const std::string& x)
{
    Table fromFile{2};
    fromFile.parseFile(x);

    for(const auto& ff : fromFile)
    {
        this->symbolic_data.push_back(SymbolicData(ff));
    }

    std::cerr << " # Number of symbolic_data: " << this->symbolic_data.size() << std::endl;
}

void DisasmData::parseSymbolMinusSymbol(const std::string& x)
{
    this->symbol_minus_symbol.parseFile(x);
    std::cerr << " # Number of symbol_minus_symbol: " << this->symbol_minus_symbol.size()
              << std::endl;
}

void DisasmData::parseMovedDataLabel(const std::string& x)
{
    this->moved_data_label.parseFile(x);
    std::cerr << " # Number of moved_data_label: " << this->moved_data_label.size() << std::endl;
}

void DisasmData::parseString(const std::string& x)
{
    this->string.parseFile(x);
    std::cerr << " # Number of string: " << this->string.size() << std::endl;
}

void DisasmData::parseBSSData(const std::string& x)
{
    Table fromFile{1};
    fromFile.parseFile(x);

    for(const auto& ff : fromFile)
    {
        this->bss_data.push_back(boost::lexical_cast<uint64_t>(ff[0]));
    }

    std::cerr << " # Number of bss_data: " << this->bss_data.size() << std::endl;
}

void DisasmData::parseStackOperand(const std::string& x)
{
    this->stack_operand.parseFile(x);
    std::cerr << " # Number of stack_operand: " << this->stack_operand.size() << std::endl;
}

void DisasmData::parsePreferredDataAccess(const std::string& x)
{
    this->preferred_data_access.parseFile(x);
    std::cerr << " # Number of preferred_data_access: " << this->preferred_data_access.size()
              << std::endl;
}

void DisasmData::parseDataAccessPattern(const std::string& x)
{
    this->data_access_pattern.parseFile(x);
    std::cerr << " # Number of data_access_pattern: " << this->data_access_pattern.size()
              << std::endl;
}

void DisasmData::parseDiscardedBlock(const std::string& x)
{
    this->discarded_block.parseFile(x);
    std::cerr << " # Number of discarded_block: " << this->discarded_block.size() << std::endl;
}

void DisasmData::parseDirectJump(const std::string& x)
{
    this->direct_jump.parseFile(x);
    std::cerr << " # Number of direct_jump: " << this->direct_jump.size() << std::endl;
}

void DisasmData::parsePCRelativeJump(const std::string& x)
{
    this->pc_relative_jump.parseFile(x);
    std::cerr << " # Number of pc_relative_jump: " << this->pc_relative_jump.size() << std::endl;
}

void DisasmData::parsePCRelativeCall(const std::string& x)
{
    this->pc_relative_call.parseFile(x);
    std::cerr << " # Number of pc_relative_call: " << this->pc_relative_call.size() << std::endl;
}

void DisasmData::parseBlockOverlap(const std::string& x)
{
    this->block_overlap.parseFile(x);
    std::cerr << " # Number of block_overlap: " << this->block_overlap.size() << std::endl;
}

void DisasmData::parseDefUsed(const std::string& x)
{
    this->def_used.parseFile(x);
    std::cerr << " # Number of def_used: " << this->def_used.size() << std::endl;
}

void DisasmData::parsePairedDataAccess(const std::string& x)
{
    this->paired_data_access.parseFile(x);
    std::cerr << " # Number of paired_data_access: " << this->paired_data_access.size()
              << std::endl;
}

void DisasmData::parseValueReg(const std::string& x)
{
    this->value_reg.parseFile(x);
    std::cerr << " # Number of value_reg: " << this->value_reg.size() << std::endl;
}

void DisasmData::parseIncompleteCFG(const std::string& x)
{
    this->incomplete_cfg.parseFile(x);
    std::cerr << " # Number of incomplete_cfg: " << this->incomplete_cfg.size() << std::endl;
}

void DisasmData::parseNoReturn(const std::string& x)
{
    this->no_return.parseFile(x);
    std::cerr << " # Number of no_return: " << this->no_return.size() << std::endl;
}

void DisasmData::parseInFunction(const std::string& x)
{
    this->in_function.parseFile(x);
    std::cerr << " # Number of in_function: " << this->in_function.size() << std::endl;
}

std::vector<Symbol>* DisasmData::getSymbol()
{
    return &this->symbol;
}

std::vector<Section>* DisasmData::getSection()
{
    return &this->section;
}

std::vector<Relocation>* DisasmData::getRelocation()
{
    return &this->relocation;
}

std::vector<Instruction>* DisasmData::getInstruction()
{
    return &this->instruction;
}

std::vector<OpRegdirect>* DisasmData::getOPRegdirect()
{
    return &this->op_regdirect;
}

std::vector<OpImmediate>* DisasmData::getOPImmediate()
{
    return &this->op_immediate;
}

std::vector<OpIndirect>* DisasmData::getOPIndirect()
{
    return &this->op_indirect;
}

std::vector<DataByte>* DisasmData::getDataByte()
{
    return &this->data_byte;
}

std::vector<uint64_t>* DisasmData::getBlock()
{
    return &this->block;
}

std::vector<CodeInBlock>* DisasmData::getCodeInBlock()
{
    return &this->code_in_block;
}

std::vector<uint64_t>* DisasmData::getRemainingEA()
{
    return &this->remaining_ea;
}

std::vector<FunctionSymbol>* DisasmData::getFunctionSymbol()
{
    return &this->function_symbol;
}

std::vector<uint64_t>* DisasmData::getMainFunction()
{
    return &this->main_function;
}

std::vector<uint64_t>* DisasmData::getStartFunction()
{
    return &this->start_function;
}

std::vector<uint64_t>* DisasmData::getFunctionEntry()
{
    return &this->function_entry;
}

std::vector<uint64_t>* DisasmData::getAmbiguousSymbol()
{
    return &this->ambiguous_symbol;
}

std::vector<DirectCall>* DisasmData::getDirectCall()
{
    return &this->direct_call;
}

std::vector<PLTReference>* DisasmData::getPLTReference()
{
    return &this->plt_reference;
}

std::vector<SymbolicOperand>* DisasmData::getSymbolicOperand()
{
    return &this->symbolic_operand;
}

std::vector<MovedLabel>* DisasmData::getMovedLabel()
{
    return &this->moved_label;
}

std::vector<uint64_t>* DisasmData::getLabeledData()
{
    return &this->labeled_data;
}

std::vector<SymbolicData>* DisasmData::getSymbolicData()
{
    return &this->symbolic_data;
}

Table* DisasmData::getSymbolMinusSymbol()
{
    return &this->symbol_minus_symbol;
}

Table* DisasmData::getMovedDataLabel()
{
    return &this->moved_data_label;
}

Table* DisasmData::getString()
{
    return &this->string;
}

std::vector<uint64_t>* DisasmData::getBSSData()
{
    return &this->bss_data;
}

Table* DisasmData::getStackOperand()
{
    return &this->stack_operand;
}

Table* DisasmData::getPreferredDataAccess()
{
    return &this->preferred_data_access;
}

Table* DisasmData::getDataAccessPattern()
{
    return &this->data_access_pattern;
}

Table* DisasmData::getDiscardedBlock()
{
    return &this->discarded_block;
}

Table* DisasmData::getDirectJump()
{
    return &this->direct_jump;
}

Table* DisasmData::getPCRelativeJump()
{
    return &this->pc_relative_jump;
}

Table* DisasmData::getPCRelativeCall()
{
    return &this->pc_relative_call;
}

Table* DisasmData::getBlockOverlap()
{
    return &this->block_overlap;
}

Table* DisasmData::getDefUsed()
{
    return &this->def_used;
}

Table* DisasmData::getPairedDataAccess()
{
    return &this->paired_data_access;
}

Table* DisasmData::getValueReg()
{
    return &this->value_reg;
}

Table* DisasmData::getIncompleteCFG()
{
    return &this->incomplete_cfg;
}

Table* DisasmData::getNoReturn()
{
    return &this->no_return;
}

Table* DisasmData::getInFunction()
{
    return &this->in_function;
}

std::list<Block> DisasmData::getCodeBlocks() const
{
    std::list<Block> blocks;

    for(auto& blockAddress : this->block)
    {
        Block b;

        for(auto& cib : this->code_in_block)
        {
            // The instruction's block address == the block's addres.
            if(cib.BlockAddress == blockAddress)
            {
                // Push back the instruction.
                b.Instructions.push_back(cib.EA);
            }
        }

        std::sort(std::begin(b.Instructions), std::end(b.Instructions));

        b.StartingAddress = blockAddress;

        if(b.Instructions.empty() == false)
        {
            const auto address = b.Instructions.back();
            const auto inst = this->getInstructionAt(address);
            b.EndingAddress = address + inst.Size;
        }
        else
        {
            b.EndingAddress = b.StartingAddress;
        }

        blocks.push_back(std::move(b));
    }

    blocks.sort([](const auto& left, const auto& right) {
        return left.StartingAddress < right.StartingAddress;
    });

    return blocks;
}

std::string DisasmData::getSectionName(uint64_t x) const
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

// function_complete_name
std::string DisasmData::getFunctionName(uint64_t x) const
{
    for(auto& s : this->function_symbol)
    {
        if(s.EA == x)
        {
            std::stringstream name;
            name << s.Name;

            if(this->getIsAmbiguousSymbol(x) == true)
            {
                name << "_" << std::hex << x;
            }

            return name.str();
        }
    }

    if(x == this->main_function[0])
    {
        return "main";
    }
    else if(x == this->start_function[0])
    {
        return "_start";
    }

    // or is this a funciton entry?
    for(auto f : this->function_entry)
    {
        if(x == f)
        {
            std::stringstream ss;
            ss << "unknown_function_" << std::hex << x;
            return ss.str();
        }
    }

    return std::string{};
}

std::string DisasmData::getGlobalSymbolName(uint64_t ea) const
{
    for(const auto& s : this->symbol)
    {
        if(s.Base == ea)
        {
            if(s.Scope == std::string{"GLOBAL"})
            {
                // %do not print labels for symbols that have to be relocated
                auto name = DisasmData::CleanSymbolNameSuffix(s.Name);

                /// \todo
                // \+relocation(_,_,Name,_),
                // \+reserved_symbol(Name),
                // avoid_reg_name_conflics(Name,NameNew).

                return name;
            }
        }
    }

    return std::string{};
}

Instruction DisasmData::getInstructionAt(uint64_t ea) const
{
    const auto inst = std::find_if(std::begin(this->instruction), std::end(this->instruction),
                                   [ea](const auto& x) { return x.EA == ea; });

    if(inst != std::end(this->instruction))
    {
        return *inst;
    }

    return Instruction{};
}

bool DisasmData::getIsAmbiguousSymbol(uint64_t ea) const
{
    const auto found =
        std::find(std::begin(this->ambiguous_symbol), std::end(this->ambiguous_symbol), ea);
    return found != std::end(this->ambiguous_symbol);
}

void DisasmData::AdjustPadding(std::list<Block>& blocks)
{
    for(auto i = std::begin(blocks); i != std::end(blocks); ++i)
    {
        auto next = i;
        ++next;
        if(next != std::end(blocks))
        {
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
}

std::string DisasmData::CleanSymbolNameSuffix(std::string x)
{
    return x.substr(0, x.find_first_of('@'));
}

std::string DisasmData::AdaptOpcode(const std::string& x)
{
    const std::map<std::string, std::string> adapt{{"movsd2", "movsd"}, {"imul2", "imul"},
                                                   {"imul3", "imul"},   {"imul1", "imul"},
                                                   {"cmpsd3", "cmpsd"}, {"out_i", "out"}};

    const auto found = adapt.find(x);
    if(found != std::end(adapt))
    {
        return found->second;
    }

    return x;
}

std::string DisasmData::AdaptRegister(const std::string& x)
{
    const std::map<std::string, std::string> adapt{
        {"R8L", "R8B"},   {"R9L", "R9B"},   {"R10L", "R10B"}, {"R11L", "R11B"}, {"R12L", "R12B"},
        {"R13L", "R13B"}, {"R14L", "R14B"}, {"R15L", "R15B"}, {"R12L", "R12B"}, {"R13L", "R13B"},
        {"ST0", "ST(0)"}, {"ST1", "ST(1)"}, {"ST2", "ST(2)"}, {"ST3", "ST(3)"}, {"ST4", "ST(4)"},
        {"ST5", "ST(5)"}, {"ST6", "ST(6)"}, {"ST7", "ST(7)"}};

    const auto found = adapt.find(x);
    if(found != std::end(adapt))
    {
        return found->second;
    }

    return x;
}

std::string DisasmData::GetSizeName(uint64_t x)
{
    return DisasmData::GetSizeName(std::to_string(x));
}

std::string DisasmData::GetSizeName(const std::string& x)
{
    const std::map<std::string, std::string> adapt{
        {"128", ""},         {"0", ""},          {"80", "TBYTE PTR"}, {"64", "QWORD PTR"},
        {"32", "DWORD PTR"}, {"16", "WORD PTR"}, {"8", "BYTE PTR"}};

    const auto found = adapt.find(x);
    if(found != std::end(adapt))
    {
        return found->second;
    }

    assert("Unknown Size");

    return x;
}

std::string DisasmData::GetSizeSuffix(uint64_t x)
{
    return DisasmData::GetSizeSuffix(std::to_string(x));
}

std::string DisasmData::GetSizeSuffix(const std::string& x)
{
    const std::map<std::string, std::string> adapt{
        {"128", ""}, {"0", ""}, {"80", "t"}, {"64", "q"}, {"32", "d"}, {"16", "w"}, {"8", "b"}};

    const auto found = adapt.find(x);
    if(found != std::end(adapt))
    {
        return found->second;
    }

    assert("Unknown Size");

    return x;
}
