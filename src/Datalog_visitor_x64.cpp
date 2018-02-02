/* GT_EXTERNAL_LEGEND(2008-2010) */

#include "Datalog_visitor_x64.h"
#include "gtr/src/lang/gtr_config.h"
#include "gtr/src/string/tohex.hpp"

#include <cctype>
#include <sstream>
#include <iostream>

void Datalog_visitor_x64::collect_operands(Dl_operator_table& dict){
        for(auto op: operators){
            int64_t index=dict.add(op);
            operator_codes.push_back(index);
        }
}
std::string Datalog_visitor_x64::result_tabs(){
    std::ostringstream o;
    o<<address<<"\t"<<size<<"\t"<<name;
    for (size_t i=0;i<4;++i){
        if(i<operator_codes.size())
            o<<"\t"<< operator_codes[i];
        else
            o<<"\t"<< 0;
    }
    return o.str();
}

std::string Datalog_visitor_x64::result(){
    std::ostringstream o;
    o<< "instruction("<<address<<","<<size<<","<<name;
    for (auto op: operators){
        o<<","<< op.print();
    }
    o<<").";
    return o.str();
}

void Datalog_visitor_x64::visit(const ConcTSLInterface::instruction * const n)
{

    std::cout<<"unrecognized instruction:"<<n->GetClassIdName()<<std::endl;
    exit(1);
}
void Datalog_visitor_x64::visit(const RTG::operand * const n)
{
    std::cout<<"unrecognized operator:"<<n->GetClassIdName() <<std::endl;
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





template<typename T>
void Datalog_visitor_x64::visit1op(const  T* const n)
{
    curr_op.type=operator_type::NONE;
    n->Get_Src()->accept(*this);
    operators.push_back(curr_op);
    n->Get_OneOpInstr()->accept(*this);
}
template<typename T>
void Datalog_visitor_x64::visit2op(const T * const n)
{
    curr_op.type=operator_type::NONE;
    n->Get_Src()->accept(*this);
    operators.push_back(curr_op);

    curr_op.type=operator_type::NONE;
    n->Get_Dst() ->accept(*this);
    operators.push_back(curr_op);

    n->Get_TwoOpInstr()->accept(*this);
}
template<typename T>
void Datalog_visitor_x64::visit3op(const T * const n)
{
    curr_op.type=operator_type::NONE;
    n->Get_Src1()->accept(*this);
    operators.push_back(curr_op);

    curr_op.type=operator_type::NONE;
    n->Get_Src2()->accept(*this);
    operators.push_back(curr_op);

    curr_op.type=operator_type::NONE;
    n->Get_Dst() ->accept(*this);
    operators.push_back(curr_op);

    n->Get_ThreeOpInstr()->accept(*this);
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
    curr_op.type=operator_type::REG;
    curr_op.reg1=std::string(n->Get_Reg()->GetClassIdName());
}
void Datalog_visitor_x64::visit(const RTG::RegDirect64 * const n)
{
    curr_op.type=operator_type::REG;
    curr_op.reg1=std::string(n->Get_Reg()->GetClassIdName());
}
void Datalog_visitor_x64::visit(const RTG::RegDirect32 * const n)
{
    curr_op.type=operator_type::REG;
    curr_op.reg1=std::string(n->Get_Reg()->GetClassIdName());
}
void Datalog_visitor_x64::visit(const RTG::RegDirect16 * const n)
{
    curr_op.type=operator_type::REG;
    curr_op.reg1=std::string(n->Get_Reg()->GetClassIdName());
}
void Datalog_visitor_x64::visit(const RTG::RegDirect8 * const n)
{
    curr_op.type=operator_type::REG;
    curr_op.reg1=std::string(n->Get_Reg()->GetClassIdName());
}



void Datalog_visitor_x64::visit(const RTG::SRegDirect64 * const n)
{
    curr_op.type=operator_type::REG;
    curr_op.reg1=std::string(n->Get_Reg()->GetClassIdName());
}
void Datalog_visitor_x64::visit(const RTG::SRegDirect32 * const n)
{
    curr_op.type=operator_type::REG;
    curr_op.reg1=std::string(n->Get_Reg()->GetClassIdName());
}
void Datalog_visitor_x64::visit(const RTG::SRegDirect16 * const n)
{
    curr_op.type=operator_type::REG;
    curr_op.reg1=std::string(n->Get_Reg()->GetClassIdName());
}

void Datalog_visitor_x64::visit(const RTG::Float_RegDirect * const n)
{
    curr_op.type=operator_type::REG;
    curr_op.reg1=std::string(n->Get_Reg()->GetClassIdName());
}

template <typename addr>
void Datalog_visitor_x64::visitAddr(const addr * const n){
        curr_op.type=operator_type::INDIRECT;
        curr_op.reg1=n->Get_Seg()->GetClassIdName();
        curr_op.reg2=n->Get_Base()->GetClassIdName();
        curr_op.reg3=n->Get_Index()->GetClassIdName();


        curr_op.disp= n->Get_disp().get_data();
        curr_op.offset= n->Get_offset().get_data();
        curr_op.multiplier=n->Get_s().get_data();
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
    operators.push_back(curr_op);
    }
    void Datalog_visitor_x64::visit(const RTG::FarIndirect16 * const n)
    {
    name=n->GetClassIdName();
    curr_op.type=operator_type::NONE;
    n->Get_Addr() ->accept(*this);
    operators.push_back(curr_op);
    }
    void Datalog_visitor_x64::visit(const RTG::FarIndirect32 * const n)
    {
      name=n->GetClassIdName();
    curr_op.type=operator_type::NONE;
    n->Get_Addr() ->accept(*this);
    operators.push_back(curr_op);
    }
    void Datalog_visitor_x64::visit(const RTG::FarIndirect64 * const n)
    {
    name=n->GetClassIdName();
    curr_op.type=operator_type::NONE;
    n->Get_Addr() ->accept(*this);
    operators.push_back(curr_op);
    }

    void Datalog_visitor_x64::visit(const RTG::Lea64 * const n)
    {
    name=n->GetClassIdName();
    curr_op.type=operator_type::NONE;
    n->Get_Addr() ->accept(*this);
    operators.push_back(curr_op);

    curr_op.type=operator_type::NONE;
    n->Get_Dst() ->accept(*this);
    operators.push_back(curr_op);
    }
    void Datalog_visitor_x64::visit(const RTG::Lea32 * const n)
    {
    name=n->GetClassIdName();
    curr_op.type=operator_type::NONE;
    n->Get_Addr() ->accept(*this);
    operators.push_back(curr_op);

    curr_op.type=operator_type::NONE;
    n->Get_Dst() ->accept(*this);
    operators.push_back(curr_op);
    }
    void Datalog_visitor_x64::visit(const RTG::Lea16 * const n)
    {
       name=n->GetClassIdName();
    curr_op.type=operator_type::NONE;
    n->Get_Addr() ->accept(*this);
    operators.push_back(curr_op);

    curr_op.type=operator_type::NONE;
    n->Get_Dst() ->accept(*this);
    operators.push_back(curr_op);
    }
    void Datalog_visitor_x64::visit(const RTG::Fnstenv * const n)
    {
       name=n->GetClassIdName();
    curr_op.type=operator_type::NONE;
    n->Get_Addr() ->accept(*this);
    operators.push_back(curr_op);


    }
    void Datalog_visitor_x64::visit(const RTG::Fldenv * const n)
    {
         name=n->GetClassIdName();
    curr_op.type=operator_type::NONE;
    n->Get_Addr() ->accept(*this);
    operators.push_back(curr_op);
    }
    void Datalog_visitor_x64::visit(const RTG::Fnsave * const n)
    {
          name=n->GetClassIdName();
    curr_op.type=operator_type::NONE;
    n->Get_Addr() ->accept(*this);
    operators.push_back(curr_op);
    }
    void Datalog_visitor_x64::visit(const RTG::Frstor * const n)
    {
           name=n->GetClassIdName();
    curr_op.type=operator_type::NONE;
    n->Get_Addr() ->accept(*this);
    operators.push_back(curr_op);
    }
    void Datalog_visitor_x64::visit(const RTG::Fxsave * const n)
    {
        name=n->GetClassIdName();
    curr_op.type=operator_type::NONE;
    n->Get_Addr() ->accept(*this);
    operators.push_back(curr_op);
    }
    void Datalog_visitor_x64::visit(const RTG::Fxsave64 * const n)
    {
          name=n->GetClassIdName();
    curr_op.type=operator_type::NONE;
    n->Get_Addr() ->accept(*this);
    operators.push_back(curr_op);
    }
    void Datalog_visitor_x64::visit(const RTG::Fxrstor * const n)
    {
          name=n->GetClassIdName();
    curr_op.type=operator_type::NONE;
    n->Get_Addr() ->accept(*this);
    operators.push_back(curr_op);
    }
    void Datalog_visitor_x64::visit(const RTG::Fxrstor64 * const n)
    {
             name=n->GetClassIdName();
    curr_op.type=operator_type::NONE;
    n->Get_Addr() ->accept(*this);
    operators.push_back(curr_op);
    }
    void Datalog_visitor_x64::visit(const RTG::Xsave * const n)
    {
              name=n->GetClassIdName();
    curr_op.type=operator_type::NONE;
    n->Get_Addr() ->accept(*this);
    operators.push_back(curr_op);
    }
    void Datalog_visitor_x64::visit(const RTG::Xsave64 * const n)
    {
             name=n->GetClassIdName();
    curr_op.type=operator_type::NONE;
    n->Get_Addr() ->accept(*this);
    operators.push_back(curr_op);
    }
    void Datalog_visitor_x64::visit(const RTG::Xrstor * const n)
    {
          name=n->GetClassIdName();
    curr_op.type=operator_type::NONE;
    n->Get_Addr() ->accept(*this);
    operators.push_back(curr_op);
    }
    void Datalog_visitor_x64::visit(const RTG::Xrstor64 * const n)
    {
          name=n->GetClassIdName();
    curr_op.type=operator_type::NONE;
    n->Get_Addr() ->accept(*this);
    operators.push_back(curr_op);
    }
    void Datalog_visitor_x64::visit(const RTG::Invlpg * const n)
    {
    name=n->GetClassIdName();
    curr_op.type=operator_type::NONE;
    n->Get_Addr() ->accept(*this);
    operators.push_back(curr_op);
    }
