/*
 * dl_operator.cpp
 *
 *  Created on: Feb 1, 2018
 *      Author: afloresmontoya
 */

#include "Dl_operator.h"
#include <sstream>


std::string Dl_operator::print() const{
    std::ostringstream o;
    switch(type){
    case NONE:
    default:
        return "none";
    case REG:
        o<< reg1;
        return o.str();
    case IMMEDIATE:
        o<< "immediate("<<offset<<")";
        return o.str();
    case INDIRECT:
        o<< "indirect("<<reg1<<","<<reg2<<","<<reg3<<","<<multiplier<<","<<offset<<")";
        return o.str();
    }
}
std::string Dl_operator::print_tabs(int64_t id) const{
    std::ostringstream o;
    switch(type){
    case NONE:
    default:
        return "none";
    case REG:
        o<<id<<'\t'<< reg1;
        return o.str();
    case IMMEDIATE:
        o<< id<< '\t'<<offset;
        return o.str();
    case INDIRECT:
        o<< id<<'\t'<<reg1<<'\t'<<reg2<<'\t'<<reg3<<'\t'<<multiplier<<'\t'<<offset<<'\t'<< size;;
        return o.str();
    }
}


operator_type Dl_operator::get_type() const{
    return type;
}


bool compare_operators::operator()(const Dl_operator&  op1,const Dl_operator&  op2) const{
    if(op1.type==op2.type){
        switch(op1.type){
        case NONE:
            return false;
        case REG:
            return  op1.size< op2.size ||
                    (op1.size== op2.size && op1.reg1< op2.reg1) ;
        case IMMEDIATE:
            return op1.size< op2.size ||
                    (op1.size== op2.size && op1.offset< op2.offset);
        case INDIRECT:

            return op1.size< op2.size ||
                    (op1.size== op2.size && op1.reg1< op2.reg1) ||
                    ((op1.size== op2.size) &&  (op1.reg1==op2.reg1) && (op1.reg2< op2.reg2)) ||
                    ((op1.size== op2.size) && (op1.reg1==op2.reg1) && (op1.reg2==op2.reg2) && (op1.reg3< op2.reg3)) ||
                    ( (op1.size== op2.size) && (op1.reg1==op2.reg1) && (op1.reg2==op2.reg2) && (op1.reg3==op2.reg3) &&
                            (op1.offset< op2.offset)) ||
                            ( (op1.size== op2.size) && (op1.reg1==op2.reg1) && (op1.reg2==op2.reg2) && (op1.reg3==op2.reg3) &&
                                    (op1.offset==op2.offset) && (op1.multiplier< op2.multiplier) );
        }
    }else{
        return op1.type<op2.type;
    }
    return false;
}



