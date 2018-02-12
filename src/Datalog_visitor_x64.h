

#ifndef datalog_visitor_x64_HPP
#define datalog_visitor_x64_HPP

#include "Dl_operator.h"
#include "Dl_instruction.h"
#include "Dl_operator_table.h"
#include "isal/x64/x64_pp.hpp"
#include "isal/x64/decoderMode.h"

#include <vector>

class Datalog_visitor_x64 : public tsl_x64::Conc1LevelRTG::ConcVisitor
{
    typedef tsl_x64::Conc1LevelRTG RTG;
private:
    template<typename T>  void visit3op(const T * const n,short size1,short size2, short size3);
    template<typename T>  void visit2op(const T * const n,short size1,short size2);
    template<typename T>  void visit1op(const T * const n,short size);
    template<typename T>  void visitAddr(const T * const n);
    template<typename T>  void visitRegDirect(const T * const n);
    template<typename T>  void visitInstrWAdrr(const T * const n);
    template<typename T>  void visitInstrWAdrrDst(const T * const n);

    void add_curr_operator();


    int64_t address;
    long size;
    std::string name;
    Dl_operator curr_op;
    std::vector<int64_t> op_codes;
    Dl_operator_table* op_dict;
public:

    explicit Datalog_visitor_x64(int64_t address,long size,Dl_operator_table* op_dict)
    : address(address)
    , size(size)
    , name("unsupported:")
    , curr_op()
    , op_codes()
    {
        this->op_dict=op_dict;
    }

    //std::string result();
    Dl_instruction get_instruction();
    //generic instruction
    virtual void visit(const ConcTSLInterface::instruction * const n);
    //generic operand
    virtual void visit(const RTG::operand * const n);

    //these types contain the names of the instructions
    virtual void visit(const RTG::threeOpInstr * const p);
    virtual void visit(const RTG::twoOpInstr * const p);
    virtual void visit(const RTG::oneOpInstr * const p);
    virtual void visit(const RTG::zeroOpInstr * const p);
    // special instructions
    virtual void visit(const  RTG::ZeroOp* const n){ n->Get_ZeroOpInstr()->accept(*this);}
    virtual void visit(const  RTG::Ret* const n){name=n->GetClassIdName();}
    virtual void visit(const  RTG::FarRet* const n){name=n->GetClassIdName();}
    virtual void visit(const  RTG::IRet64* const n){name=n->GetClassIdName();}
    virtual void visit(const  RTG::IRet32* const n){name=n->GetClassIdName();}
    virtual void visit(const  RTG::IRet16* const n){name=n->GetClassIdName();}
    //one op
    virtual void visit(const RTG::OneOpFloat * const n){ visit1op<RTG::OneOpFloat>(n,64); }
    virtual void visit(const RTG::OneOp128 * const n){ visit1op<RTG::OneOp128>(n,128); }
    virtual void visit(const RTG::OneOp80 * const n){ visit1op<RTG::OneOp80>(n,80); }
    virtual void visit(const RTG::OneOp64 * const n){ visit1op<RTG::OneOp64>(n,64); }
    virtual void visit(const RTG::OneOp32 * const n){ visit1op<RTG::OneOp32>(n,32); }
    virtual void visit(const RTG::OneOp16 * const n){ visit1op<RTG::OneOp16>(n,16); }
    virtual void visit(const RTG::OneOp8 * const n){ visit1op<RTG::OneOp8>(n,8); }

    //two operands
    virtual void visit(const RTG::TwoOp128_64 * const n){ visit2op<RTG::TwoOp128_64>(n,128,64); }
    virtual void visit(const RTG::TwoOp128_32 * const n){ visit2op<RTG::TwoOp128_32>(n,128,32); }
    virtual void visit(const RTG::TwoOp128_16 * const n){ visit2op<RTG::TwoOp128_16>(n,128,16); }
    virtual void visit(const RTG::TwoOp128_8 * const n){ visit2op<RTG::TwoOp128_8>(n,128,8); }

    virtual void visit(const RTG::TwoOp64_128 * const n){ visit2op<RTG::TwoOp64_128>(n,64,128); }
    virtual void visit(const RTG::TwoOp64_32 * const n){ visit2op<RTG::TwoOp64_32>(n,64,32); }
    virtual void visit(const RTG::TwoOp64_16 * const n){ visit2op<RTG::TwoOp64_16>(n,64,16); }
    virtual void visit(const RTG::TwoOp64_8 * const n){ visit2op<RTG::TwoOp64_8>(n,64,8); }

    virtual void visit(const RTG::TwoOp32_128 * const n){ visit2op<RTG::TwoOp32_128>(n,32,128); }
    virtual void visit(const RTG::TwoOp32_64 * const n){ visit2op<RTG::TwoOp32_64>(n,32,64); }
    virtual void visit(const RTG::TwoOp32_48 * const n){ visit2op<RTG::TwoOp32_48>(n,32,48); }
    virtual void visit(const RTG::TwoOp32_16 * const n){ visit2op<RTG::TwoOp32_16>(n,32,16); }
    virtual void visit(const RTG::TwoOp32_8 * const n){ visit2op<RTG::TwoOp32_8>(n,32,8); }


    virtual void visit(const RTG::TwoOp16_64 * const n){ visit2op<RTG::TwoOp16_64>(n,16,64); }
    virtual void visit(const RTG::TwoOp16_32 * const n){ visit2op<RTG::TwoOp16_32>(n,16,32); }
    virtual void visit(const RTG::TwoOp16_8 * const n){ visit2op<RTG::TwoOp16_8>(n,16,8); }

    virtual void visit(const RTG::TwoOp8_32 * const n){ visit2op<RTG::TwoOp8_32>(n,8,32); }
    virtual void visit(const RTG::TwoOp8_16 * const n){ visit2op<RTG::TwoOp8_16>(n,8,16); }


    virtual void visit(const RTG::TwoOp128 * const n){ visit2op<RTG::TwoOp128>(n,128,128); }
    virtual void visit(const RTG::TwoOp64 * const n){ visit2op<RTG::TwoOp64>(n,64,64); }
    virtual void visit(const RTG::TwoOp32 * const n){ visit2op<RTG::TwoOp32>(n,32,32); }
    virtual void visit(const RTG::TwoOp16 * const n){ visit2op<RTG::TwoOp16>(n,16,16); }
    virtual void visit(const RTG::TwoOp8 * const n){ visit2op<RTG::TwoOp8>(n,8,8); }
    // three operands
    virtual void visit(const RTG::ThreeOp32_32_32 * const n){ visit3op<RTG::ThreeOp32_32_32>(n,32,32,32); }
    virtual void visit(const RTG::ThreeOp16_16_16 * const n){ visit3op<RTG::ThreeOp16_16_16>(n,16,16,16); }
    virtual void visit(const RTG::ThreeOp128 * const n){ visit3op<RTG::ThreeOp128>(n,128,128,128); }

    virtual void visit(const RTG::ThreeOp128_128_8 * const n){ visit3op<RTG::ThreeOp128_128_8>(n,128,128,8); }
    virtual void visit(const RTG::ThreeOp128_64_8 * const n){ visit3op<RTG::ThreeOp128_64_8>(n,128,64,8); }
    virtual void visit(const RTG::ThreeOp128_32_8 * const n){ visit3op<RTG::ThreeOp128_32_8>(n,128,32,8); }
    virtual void visit(const RTG::ThreeOp128_16_8 * const n){ visit3op<RTG::ThreeOp128_16_8>(n,128,16,8); }
    virtual void visit(const RTG::ThreeOp128_8_8 * const n){ visit3op<RTG::ThreeOp128_8_8>(n,128,8,8); }

    virtual void visit(const RTG::ThreeOp64_64_32 * const n){ visit3op<RTG::ThreeOp64_64_32>(n,64,64,32); }
    virtual void visit(const RTG::ThreeOp64_64_8 * const n){ visit3op<RTG::ThreeOp64_64_8>(n,64,64,8); }

    virtual void visit(const RTG::ThreeOp64_32_8 * const n){ visit3op<RTG::ThreeOp64_32_8>(n,64,32,8); }
    virtual void visit(const RTG::ThreeOp64_16_8 * const n){ visit3op<RTG::ThreeOp64_16_8>(n,64,16,8); }
    virtual void visit(const RTG::ThreeOp64_128_8 * const n){ visit3op<RTG::ThreeOp64_128_8>(n,64,128,8); }



    virtual void visit(const RTG::ThreeOp32_128_8 * const n){ visit3op<RTG::ThreeOp32_128_8>(n,32,128,8); }
    virtual void visit(const RTG::ThreeOp32_64_8 * const n){ visit3op<RTG::ThreeOp32_64_8>(n,32,64,8); }
    virtual void visit(const RTG::ThreeOp32_32_8 * const n){ visit3op<RTG::ThreeOp32_32_8>(n,32,32,8); }

    virtual void visit(const RTG::ThreeOp16_128_8 * const n){ visit3op<RTG::ThreeOp16_128_8>(n,16,128,8); }
    virtual void visit(const RTG::ThreeOp16_16_8 * const n){ visit3op<RTG::ThreeOp16_16_8>(n,16,16,8); }

    virtual void visit(const RTG::ThreeOp8_128_8 * const n){ visit3op<RTG::ThreeOp8_128_8>(n,8,128,8); }

    // operands
    virtual void visit(const RTG::OperandFloat * const n);
    virtual void visit(const RTG::Operand128 * const n);
    virtual void visit(const RTG::Operand80 * const n);
    virtual void visit(const RTG::Operand64 * const n);
    virtual void visit(const RTG::Operand48 * const n);
    virtual void visit(const RTG::Operand32 * const n);
    virtual void visit(const RTG::Operand16 * const n);
    virtual void visit(const RTG::Operand8 * const n);
    // addresses
    //virtual void visit(const RTG::Addr64 * const n);
    virtual void visit(const RTG::Addr64 * const n){ visitAddr<RTG::Addr64>(n);}
    virtual void visit(const RTG::Addr32 * const n){ visitAddr<RTG::Addr32>(n);}
    //    virtual void visit(const RTG::Addr16 * const n){ visitAddr<RTG::Addr16>(n);}

    //registers
    virtual void visit(const RTG::RegDirect128 * const n);
    virtual void visit(const RTG::RegDirect64 * const n);
    virtual void visit(const RTG::RegDirect32 * const n);
    virtual void visit(const RTG::RegDirect16 * const n);
    virtual void visit(const RTG::RegDirect8 * const n);

    virtual void visit(const RTG::SRegDirect64 * const n);
    virtual void visit(const RTG::SRegDirect32 * const n);
    virtual void visit(const RTG::SRegDirect16 * const n);

    virtual void visit(const RTG::Float_RegDirect * const n);


    // virtual void visit(const RTG::reg * const n);

    // immediate operands
    virtual void visit(const RTG::Immediate64 * const n);
    virtual void visit(const RTG::Immediate32 * const n);
    virtual void visit(const RTG::Immediate16 * const n);
    virtual void visit(const RTG::Immediate8 * const n);
    // indirect operands
    virtual void visit(const RTG::Indirect128 * const n);
    virtual void visit(const RTG::Indirect80 * const n);
    virtual void visit(const RTG::Indirect64 * const n);
    virtual void visit(const RTG::Indirect48 * const n);
    virtual void visit(const RTG::Indirect32 * const n);
    virtual void visit(const RTG::Indirect16 * const n);
    virtual void visit(const RTG::Indirect8 * const n);

    // other operands

    virtual void visit(const RTG::Float_Int64 * const n){
        n->Get_Addr() ->accept(*this);
    }
    virtual void visit(const RTG::Float_Int32 * const n){
        n->Get_Addr() ->accept(*this);
    }
    virtual void visit(const RTG::Float_Int16 * const n){
        n->Get_Addr() ->accept(*this);
    }
    virtual void visit(const RTG::Float_Real80 * const n){
        n->Get_Addr() ->accept(*this);
    }
    virtual void visit(const RTG::Float_Real64 * const n){
        n->Get_Addr() ->accept(*this);
    }
    virtual void visit(const RTG::Float_Real32 * const n){
        n->Get_Addr() ->accept(*this);
    }



    //special instructions


    // special instructions
    virtual void visit(const RTG::FarImmediate * const n);
    virtual void visit(const RTG::FarIndirect16 * const n);
    virtual void visit(const RTG::FarIndirect32 * const n);
    virtual void visit(const RTG::FarIndirect64 * const n);
    virtual void visit(const RTG::Lea64 * const n);
    virtual void visit(const RTG::Lea32 * const n);
    virtual void visit(const RTG::Lea16 * const n);
    virtual void visit(const RTG::Fnstenv * const n);
    virtual void visit(const RTG::Fldenv * const n);
    virtual void visit(const RTG::Fnsave * const n);
    virtual void visit(const RTG::Frstor * const n);
    virtual void visit(const RTG::Fxsave * const n);
    virtual void visit(const RTG::Fxsave64 * const n);
    virtual void visit(const RTG::Fxrstor * const n);
    virtual void visit(const RTG::Fxrstor64 * const n);
    virtual void visit(const RTG::Xsave * const n);
    virtual void visit(const RTG::Xsave64 * const n);
    virtual void visit(const RTG::Xrstor * const n);
    virtual void visit(const RTG::Xrstor64 * const n);
    virtual void visit(const RTG::Invlpg * const n);

};

#endif // datalog_visitor_x64
