

#include "Datalog_visitor_x64.h"
#include "gtr/src/lang/gtr_config.h"
#include "gtr/src/string/tohex.hpp"

#include <exception>
#include <algorithm>


void Datalog_visitor_x64::add_curr_operator(){
    if (curr_op.type==operator_type::NONE){
        std::ostringstream error_message;
        error_message<<"An operator has not been processed well in EA: "<< address;
        throw std::logic_error(error_message.str());
    }
    int64_t index=op_dict->add(curr_op);
    op_codes.push_back(index);
}

Dl_instruction Datalog_visitor_x64::get_instruction(){
    return Dl_instruction(address,size,prefix+name,op_codes);
}

void Datalog_visitor_x64::set_prefix(uint attrib)
{
    if (attrib & 1) prefix=  "rep ";
    else if (attrib & 2) prefix= "repe ";
    else if (attrib & 4) prefix="repne ";
    if (attrib & 8) prefix= "lock ";
}
/*
std::string Datalog_visitor_x64::result(){
    std::ostringstream o;
    o<< "instruction("<<address<<","<<size<<","<<name;
    for (auto op: operators){
        o<<","<< op.print();
    }
    o<<").";
    return o.str();
}
 */

void Datalog_visitor_x64::visit(const ConcTSLInterface::instruction * const n)
{
    std::cerr<<"unrecognized instruction:"<<n->GetClassIdName()<<std::endl;
    exit(1);
}
void Datalog_visitor_x64::visit(const RTG::operand * const n)
{
    std::cerr<<"unrecognized operator:"<<n->GetClassIdName() <<std::endl;
    exit(1);
}



void Datalog_visitor_x64::visit(const RTG::threeOpInstr * const p){
    name=std::string(p->GetClassIdName());
}
void Datalog_visitor_x64::visit(const RTG::twoOpInstr * const p){
    name=std::string(p->GetClassIdName());

}
void Datalog_visitor_x64::visit(const RTG::oneOpInstr * const p){
    name=std::string(p->GetClassIdName());
}
void Datalog_visitor_x64::visit(const RTG::zeroOpInstr * const p){
    name=std::string(p->GetClassIdName());
}

// this is a workaround to the fact that the ast sizes sometimes do no correspond to the actual
// sizes of the operands
void Datalog_visitor_x64::fix_size_exceptions(){
    std::vector<std::string> operations {"MOVHPS","MOVHPD","MOVLPD","MOVLPS","MOVQ"};

    if(std::find(operations.begin(), operations.end(), name) != operations.end()
            && curr_op.type==operator_type::INDIRECT)
        curr_op.size=64;
}

template<typename T>
inline void Datalog_visitor_x64::visit1op(const  T* const n,short size)
{
    set_prefix(n->Get_attributes().get_data());
    n->Get_OneOpInstr()->accept(*this);
    // we put the curr_op type to none to detect cases where something went wrong
    curr_op.type=operator_type::NONE;
    curr_op.size=size;
    n->Get_Src()->accept(*this);
    add_curr_operator();

}
template<typename T>
inline void Datalog_visitor_x64::visit2op(const T * const n,short size1,short size2)
{
    set_prefix(n->Get_attributes().get_data());
    n->Get_TwoOpInstr()->accept(*this);
    curr_op.type=operator_type::NONE;
    curr_op.size=size2;
    n->Get_Src()->accept(*this);
    fix_size_exceptions();
    add_curr_operator();

    curr_op.type=operator_type::NONE;
    curr_op.size=size1;
    n->Get_Dst() ->accept(*this);
    fix_size_exceptions();
    add_curr_operator();

}
template<typename T>
inline void Datalog_visitor_x64::visit3op(const T * const n,short size1,short size2,short size3)
{
  set_prefix(n->Get_attributes().get_data());
    n->Get_ThreeOpInstr()->accept(*this);

    curr_op.type=operator_type::NONE;
    curr_op.size=size2;
    n->Get_Src1()->accept(*this);
    add_curr_operator();

    curr_op.type=operator_type::NONE;
    curr_op.size=size3;
    n->Get_Src2()->accept(*this);
    add_curr_operator();

    curr_op.type=operator_type::NONE;
    curr_op.size=size1;
    n->Get_Dst() ->accept(*this);
    add_curr_operator();

}

template<typename regdirect>
inline void Datalog_visitor_x64::visitRegDirect(const regdirect * const n)
{
    curr_op.type=operator_type::REG;
    curr_op.reg1=n->Get_Reg()->GetClassIdName();
}

template <typename addr>
inline void Datalog_visitor_x64::visitAddr(const addr * const n){
    curr_op.type=operator_type::INDIRECT;
    curr_op.reg1=n->Get_Seg()->GetClassIdName();
    curr_op.reg2=n->Get_Base()->GetClassIdName();
    curr_op.reg3=n->Get_Index()->GetClassIdName();


    curr_op.disp= n->Get_disp().get_data();
    curr_op.offset= n->Get_offset().get_data();
    curr_op.multiplier=n->Get_s().get_data();
}

template <typename instr>
inline void Datalog_visitor_x64::visitInstrWAdrr(const instr * const n)
{
    set_prefix(n->Get_attributes().get_data());
    name=n->GetClassIdName();

    curr_op.type=operator_type::NONE;
    n->Get_Addr() ->accept(*this);
    add_curr_operator();
}

template <typename instr>
inline void Datalog_visitor_x64::visitInstrWAdrrDst(const instr * const n)
{
    set_prefix(n->Get_attributes().get_data());
    name=n->GetClassIdName();

    curr_op.type=operator_type::NONE;
    n->Get_Addr() ->accept(*this);
    add_curr_operator();

    curr_op.type=operator_type::NONE;
    n->Get_Dst() ->accept(*this);
    add_curr_operator();
}

void Datalog_visitor_x64::visit(const RTG::OperandFloat * const n)
{
    n->Get_opnd() ->accept(*this);
}
void Datalog_visitor_x64::visit(const RTG::Operand128 * const n)
{
    n->Get_opnd()->accept(*this);
}
void Datalog_visitor_x64::visit(const RTG::Operand80 * const n)
{
    n->Get_opnd()->accept(*this);
}
void Datalog_visitor_x64::visit(const RTG::Operand64 * const n)
{
    n->Get_opnd()->accept(*this);
}
void Datalog_visitor_x64::visit(const RTG::Operand48 * const n)
{
    n->Get_opnd()->accept(*this);
}
void Datalog_visitor_x64::visit(const RTG::Operand32 * const n)
{
    n->Get_opnd()->accept(*this);
}
void Datalog_visitor_x64::visit(const RTG::Operand16 * const n)
{
    n->Get_opnd()->accept(*this);
}
void Datalog_visitor_x64::visit(const RTG::Operand8 * const n)
{
    n->Get_opnd()->accept(*this);
}


void Datalog_visitor_x64::visit(const RTG::RegDirect128 * const n)
{
    visitRegDirect<RTG::RegDirect128>(n);
}
void Datalog_visitor_x64::visit(const RTG::RegDirect64 * const n)
{
    visitRegDirect<RTG::RegDirect64>(n);
}
void Datalog_visitor_x64::visit(const RTG::RegDirect32 * const n)
{
    visitRegDirect<RTG::RegDirect32>(n);
}
void Datalog_visitor_x64::visit(const RTG::RegDirect16 * const n)
{
    visitRegDirect<RTG::RegDirect16>(n);
}
void Datalog_visitor_x64::visit(const RTG::RegDirect8 * const n)
{
    visitRegDirect<RTG::RegDirect8>(n);
}
void Datalog_visitor_x64::visit(const RTG::SRegDirect64 * const n)
{
    visitRegDirect<RTG::SRegDirect64>(n);
}
void Datalog_visitor_x64::visit(const RTG::SRegDirect32 * const n)
{
    visitRegDirect<RTG::SRegDirect32>(n);
}
void Datalog_visitor_x64::visit(const RTG::SRegDirect16 * const n)
{
    visitRegDirect<RTG::SRegDirect16>(n);
}
void Datalog_visitor_x64::visit(const RTG::CRegDirect64 * const n)
{
    visitRegDirect<RTG::CRegDirect64>(n);
}
void Datalog_visitor_x64::visit(const RTG::CRegDirect32 * const n)
{
    visitRegDirect<RTG::CRegDirect32>(n);
}
void Datalog_visitor_x64::visit(const RTG::DRegDirect64 * const n)
{
    visitRegDirect<RTG::DRegDirect64>(n);
}
void Datalog_visitor_x64::visit(const RTG::DRegDirect32 * const n)
{
    visitRegDirect<RTG::DRegDirect32>(n);
}
void Datalog_visitor_x64::visit(const RTG::Float_RegDirect * const n)
{
    visitRegDirect<RTG::Float_RegDirect>(n);
}



void Datalog_visitor_x64::visit(const RTG::Indirect128 * const n)
{
    n->Get_Addr()->accept(*this);
}
void Datalog_visitor_x64::visit(const RTG::Indirect80 * const n)
{
    n->Get_Addr()->accept(*this);
}
void Datalog_visitor_x64::visit(const RTG::Indirect64 * const n)
{
    n->Get_Addr()->accept(*this);
}


void Datalog_visitor_x64::visit(const RTG::Indirect48 * const n)
{
    n->Get_Addr()->accept(*this);
}
void Datalog_visitor_x64::visit(const RTG::Indirect32 * const n)
{
    n->Get_Addr()->accept(*this);
}
void Datalog_visitor_x64::visit(const RTG::Indirect16 * const n)
{
    n->Get_Addr()->accept(*this);
}
void Datalog_visitor_x64::visit(const RTG::Indirect8 * const n)
{
    n->Get_Addr()->accept(*this);
}



void Datalog_visitor_x64::visit(const RTG::Immediate64 * const n)
{
    curr_op.type=operator_type::IMMEDIATE;
    curr_op.offset=n->Get_Imm()->get_data();
}
void Datalog_visitor_x64::visit(const RTG::Immediate32 * const n)
{
    curr_op.type=operator_type::IMMEDIATE;
    curr_op.offset=n->Get_Imm()->get_data();
}
void Datalog_visitor_x64::visit(const RTG::Immediate16 * const n)
{

    curr_op.type=operator_type::IMMEDIATE;
    curr_op.offset=n->Get_Imm()->get_data();
}
void Datalog_visitor_x64::visit(const RTG::Immediate8 * const n)
{
    curr_op.type=operator_type::IMMEDIATE;
    curr_op.offset=n->Get_Imm()->get_data();
}


// special instructions
void Datalog_visitor_x64::visit(const RTG::FarImmediate * const n)
{
    name=n->GetClassIdName();
    curr_op.type=operator_type::NONE;
    n->Get_Dst() ->accept(*this);
    add_curr_operator();
}

void Datalog_visitor_x64::visit(const RTG::Lea64 * const n)
{
    visitInstrWAdrrDst<RTG::Lea64>(n);
    name="LEA";
}
void Datalog_visitor_x64::visit(const RTG::Lea32 * const n)
{
    visitInstrWAdrrDst<RTG::Lea32>(n);
    name="LEA";
}
void Datalog_visitor_x64::visit(const RTG::Lea16 * const n)
{
    visitInstrWAdrrDst<RTG::Lea16>(n);
    name="LEA";
}
void Datalog_visitor_x64::visit(const RTG::FarIndirect16 * const n)
{
    visitInstrWAdrr<RTG::FarIndirect16>(n);
}
void Datalog_visitor_x64::visit(const RTG::FarIndirect32 * const n)
{
    visitInstrWAdrr<RTG::FarIndirect32>(n);
}
void Datalog_visitor_x64::visit(const RTG::FarIndirect64 * const n)
{
    visitInstrWAdrr<RTG::FarIndirect64>(n);
}
void Datalog_visitor_x64::visit(const RTG::Fnstenv * const n)
{
    visitInstrWAdrr<RTG::Fnstenv>(n);
}
void Datalog_visitor_x64::visit(const RTG::Fldenv * const n)
{
    visitInstrWAdrr<RTG::Fldenv>(n);
}
void Datalog_visitor_x64::visit(const RTG::Fnsave * const n)
{
    visitInstrWAdrr<RTG::Fnsave>(n);
}
void Datalog_visitor_x64::visit(const RTG::Frstor * const n)
{
    visitInstrWAdrr<RTG::Frstor>(n);
}
void Datalog_visitor_x64::visit(const RTG::Fxsave * const n)
{
    visitInstrWAdrr<RTG::Fxsave>(n);
}
void Datalog_visitor_x64::visit(const RTG::Fxsave64 * const n)
{
    visitInstrWAdrr<RTG::Fxsave64>(n);
}
void Datalog_visitor_x64::visit(const RTG::Fxrstor * const n)
{
    visitInstrWAdrr<RTG::Fxrstor>(n);
}
void Datalog_visitor_x64::visit(const RTG::Fxrstor64 * const n)
{
    visitInstrWAdrr<RTG::Fxrstor64>(n);
}
void Datalog_visitor_x64::visit(const RTG::Xsave * const n)
{
    visitInstrWAdrr<RTG::Xsave>(n);
}
void Datalog_visitor_x64::visit(const RTG::Xsave64 * const n)
{
    visitInstrWAdrr<RTG::Xsave64>(n);
}
void Datalog_visitor_x64::visit(const RTG::Xrstor * const n)
{
    visitInstrWAdrr<RTG::Xrstor>(n);
}
void Datalog_visitor_x64::visit(const RTG::Xrstor64 * const n)
{
    visitInstrWAdrr<RTG::Xrstor64>(n);
}
void Datalog_visitor_x64::visit(const RTG::Invlpg * const n)
{
    visitInstrWAdrr<RTG::Invlpg>(n);
}
