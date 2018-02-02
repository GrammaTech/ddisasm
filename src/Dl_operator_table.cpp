/*
 * Dl_operator_table.cpp
 *
 *  Created on: Feb 2, 2018
 *      Author: afloresmontoya
 */

#include "Dl_operator_table.h"




int64_t Dl_operator_table::add_to_dict(op_dict& dict,Dl_operator op){
    auto pair=dict.find(op);
    if(pair!=dict.end())
        return (pair->second);
    else{
        dict[op]=curr_index;
        return curr_index++;
    }
}

int64_t Dl_operator_table::add(Dl_operator op){
   return add_to_dict(dicts[op.get_type()],op);

}
void Dl_operator_table::print(std::string directory,std::ios_base::openmode filemask){
    //skip the none dictionary
    for(int i=1;i<4;i++){
        std::ofstream file;
        file.open(directory+op_names[i]+".facts",filemask);
        for(auto pair: dicts[i]){
            file<<pair.first.print_tabs(pair.second)<<std::endl;
        }
        file.close();
    }
}
