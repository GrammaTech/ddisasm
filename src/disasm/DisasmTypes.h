#pragma once

#include <boost/lexical_cast.hpp>
#include <cstdint>
#include <string>
#include <vector>

///
///
///
struct Section
{
    Section() = default;

    Section(const std::vector<std::string>& x)
    {
        assert(x.size() == 3);

        this->Name = x[0];
        this->Size = boost::lexical_cast<uint64_t>(x[1]);
        this->StartingAddress = boost::lexical_cast<uint64_t>(x[2]);
    };

    std::string Name;
    uint64_t Size{0};
    uint64_t StartingAddress{0};
};

///
///
///
struct FunctionSymbol
{
    FunctionSymbol() = default;

    FunctionSymbol(const std::vector<std::string>& x)
    {
        assert(x.size() == 2);

        this->EA = boost::lexical_cast<uint64_t>(x[0]);
        this->Name = x[1];
    };

    std::string Name;
    uint64_t EA{0};
};

///
///
///
struct PLTReference
{
    PLTReference() = default;

    PLTReference(const std::vector<std::string>& x)
    {
        assert(x.size() == 2);

        this->EA = boost::lexical_cast<uint64_t>(x[0]);
        this->Name = x[1];
    };

    std::string Name;
    uint64_t EA{0};
};

///
///
///
struct Block
{
    Block() = default;

    // If instructions is empty, it's a NOP.
    Block(uint64_t s, uint64_t e) : StartingAddress(s), EndingAddress(e)
    {
    }

    uint64_t getSize() const
    {
        return this->EndingAddress + this->StartingAddress;
    }

    // If instructions is empty, it's a NOP.
    std::vector<uint64_t> Instructions;
    uint64_t StartingAddress{0};
    uint64_t EndingAddress{0};
};

///
///
///
struct Instruction
{
    Instruction() = default;

    Instruction(const std::vector<std::string>& x)
    {
        assert(x.size() == 6);

        this->EA = boost::lexical_cast<uint64_t>(x[0]);
        this->Size = boost::lexical_cast<uint64_t>(x[1]);
        this->Opcode = x[2];
        this->Op1 = boost::lexical_cast<uint64_t>(x[3]);
        this->Op2 = boost::lexical_cast<uint64_t>(x[4]);
        this->Op3 = boost::lexical_cast<uint64_t>(x[5]);
    };

    uint64_t getEndAddress() const
    {
        return this->EA + this->Size;
    }

    std::string Opcode;
    uint64_t EA{0};
    uint64_t Size{0};
    uint64_t Op1{0};
    uint64_t Op2{0};
    uint64_t Op3{0};
};

///
///
///
struct OpIndirect
{
    OpIndirect() = default;

    OpIndirect(const std::vector<std::string>& x)
    {
        assert(x.size() == 7);

        this->N = boost::lexical_cast<decltype(OpIndirect::N)>(x[0]);
        this->SReg = x[1];
        this->Reg1 = x[2];
        this->Reg2 = x[3];
        this->Multiplier = boost::lexical_cast<decltype(OpIndirect::Multiplier)>(x[4]);
        this->Offset = boost::lexical_cast<decltype(OpIndirect::Offset)>(x[5]);
        this->Size = boost::lexical_cast<decltype(OpIndirect::Size)>(x[6]);
    };

    uint64_t N{0};
    std::string SReg;
    std::string Reg1;
    std::string Reg2;
    int64_t Multiplier{0};
    int64_t Offset{0};
    uint64_t Size{0};
};

///
///
///
struct CodeInBlock
{
    CodeInBlock() = default;

    CodeInBlock(const std::vector<std::string>& x)
    {
        assert(x.size() == 2);

        this->EA = boost::lexical_cast<decltype(CodeInBlock::EA)>(x[0]);
        this->BlockAddress = boost::lexical_cast<decltype(CodeInBlock::BlockAddress)>(x[1]);
    };

    uint64_t EA{0};
    uint64_t BlockAddress{0};
};

///
///
///
struct Symbol
{
    Symbol() = default;

    Symbol(const std::vector<std::string>& x)
    {
        assert(x.size() == 5);

        this->Base = boost::lexical_cast<decltype(Symbol::Base)>(x[0]);
        this->Size = boost::lexical_cast<decltype(Symbol::Size)>(x[1]);
        this->Type = x[2];
        this->Scope = x[3];
        this->Name = x[4];
    };

    uint64_t Base{0};
    uint64_t Size{0};
    std::string Type;  // OBJECT, FUNC, NOTYPE
    std::string Scope; // GLOBAL, LOCAL, WEAK
    std::string Name;
};

///
///
///
struct Relocation
{
    Relocation() = default;

    Relocation(const std::vector<std::string>& x)
    {
        assert(x.size() == 4);

        this->EA = boost::lexical_cast<uint64_t>(x[0]);
        this->Label = x[1];
        this->Name = x[2];
        this->Offset = boost::lexical_cast<uint64_t>(x[3]);
    };

    uint64_t EA{0};
    std::string Label;
    std::string Name;
    uint64_t Offset{0};
};

///
///
///
struct OpRegdirect
{
    OpRegdirect() = default;

    OpRegdirect(const std::vector<std::string>& x)
    {
        assert(x.size() == 2);

        this->N = boost::lexical_cast<uint64_t>(x[0]);
        this->Register = x[1];
    };

    uint64_t N{0};
    std::string Register;
};

///
///
///
struct OpImmediate
{
    OpImmediate() = default;

    OpImmediate(const std::vector<std::string>& x)
    {
        assert(x.size() == 2);

        this->N = boost::lexical_cast<uint64_t>(x[0]);
        this->Immediate = boost::lexical_cast<int64_t>(x[1]);
    };

    uint64_t N{0};
    int64_t Immediate{0};
};

///
///
///
struct DataByte
{
    DataByte() = default;

    DataByte(const std::vector<std::string>& x)
    {
        assert(x.size() == 2);

        this->EA = boost::lexical_cast<uint64_t>(x[0]);

        // A lexical cast directly to uint8_t failed on double-digit numbers.
        const auto byte = boost::lexical_cast<int>(x[1]);
        assert(byte >= 0);
        assert(byte < 256);

        this->Content = static_cast<uint8_t>(byte);
    };

    bool operator<(const DataByte& x) const
    {
        return this->EA < x.EA;
    }

    bool operator<(const uint64_t x) const
    {
        return this->EA < x;
    }

    bool operator==(const DataByte& x) const
    {
        return this->EA == x.EA;
    }

    bool operator!=(const DataByte& x) const
    {
        return this->EA != x.EA;
    }

    bool operator==(const uint64_t x) const
    {
        return this->EA == x;
    }

    bool operator!=(const uint64_t x) const
    {
        return this->EA != x;
    }


    uint64_t EA{0};
    uint8_t Content{0};
};

///
///
///
struct DirectCall
{
    DirectCall() = default;

    DirectCall(const std::vector<std::string>& x)
    {
        assert(x.size() == 2);

        this->EA = boost::lexical_cast<uint64_t>(x[0]);
        this->Destination = boost::lexical_cast<uint64_t>(x[1]);
    };

    uint64_t EA{0};
    uint64_t Destination{0};
};

///
///
///
struct MovedLabel
{
    MovedLabel() = default;

    MovedLabel(const std::vector<std::string>& x)
    {
        assert(x.size() == 4);

        this->EA = boost::lexical_cast<uint64_t>(x[0]);
        this->N = boost::lexical_cast<int64_t>(x[1]);
        this->Offset1 = boost::lexical_cast<int64_t>(x[2]);
        this->Offset2 = boost::lexical_cast<int64_t>(x[3]);
    };

    uint64_t EA{0};
    int64_t N{0};
    int64_t Offset1{0};
    int64_t Offset2{0};
};

///
///
///
struct SymbolicOperand
{
    SymbolicOperand() = default;

    SymbolicOperand(const std::vector<std::string>& x)
    {
        assert(x.size() == 2);

        this->EA = boost::lexical_cast<uint64_t>(x[0]);
        this->OpNum = boost::lexical_cast<uint64_t>(x[1]);
    };

    uint64_t EA{0};
    uint64_t OpNum{0};
};

///
///
///
struct SymbolicData
{
    SymbolicData() = default;

    SymbolicData(const std::vector<std::string>& x)
    {
        assert(x.size() == 2);

        this->EA = boost::lexical_cast<uint64_t>(x[0]);
        this->GroupContent = boost::lexical_cast<uint64_t>(x[1]);
    };

    uint64_t EA{0};
    uint64_t GroupContent{0};
};

///
///
///
struct SymbolMinusSymbol
{
    SymbolMinusSymbol() = default;

    SymbolMinusSymbol(const std::vector<std::string>& x)
    {
        assert(x.size() == 3);

        this->EA = boost::lexical_cast<uint64_t>(x[0]);
        this->Symbol1 = boost::lexical_cast<uint64_t>(x[1]);
        this->Symbol2 = boost::lexical_cast<uint64_t>(x[2]);
    };

    uint64_t EA{0};
    uint64_t Symbol1{0};
    uint64_t Symbol2{0};
};

///
///
///
struct MovedDataLabel
{
    MovedDataLabel() = default;

    MovedDataLabel(const std::vector<std::string>& x)
    {
        assert(x.size() == 3);

        this->EA = boost::lexical_cast<uint64_t>(x[0]);
        this->Old = boost::lexical_cast<uint64_t>(x[1]);
        this->New = boost::lexical_cast<uint64_t>(x[2]);
    };

    uint64_t EA{0};
    uint64_t Old{0};
    uint64_t New{0};
};

///
/// "String" is a bad name for this data type. 
///
struct String
{
    String() = default;

    String(const std::vector<std::string>& x)
    {
        assert(x.size() == 2);

        this->EA = boost::lexical_cast<uint64_t>(x[0]);
        this->End = boost::lexical_cast<uint64_t>(x[1]);
    };

    uint64_t size() const
    {
    	return this->End - this->EA;
    }

    uint64_t EA{0};
    uint64_t End{0};
};
