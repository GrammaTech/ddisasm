//===- DwarfMap.h -----------------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2020 GrammaTech, Inc.
//
//  This code is licensed under the GNU Affero General Public License
//  as published by the Free Software Foundation, either version 3 of
//  the License, or (at your option) any later version. See the
//  LICENSE.txt file in the project root for license terms or visit
//  https://www.gnu.org/licenses/agpl.txt.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
//  GNU Affero General Public License for more details.
//
//  This project is sponsored by the Office of Naval Research, One Liberty
//  Center, 875 N. Randolph Street, Arlington, VA 22203 under contract #
//  N68335-17-C-0700.  The content of the information does not necessarily
//  reflect the position or policy of the Government and no official
//  endorsement should be inferred.
//
//===----------------------------------------------------------------------===//

#ifndef SRC_DL_DWARFMAP_H_
#define SRC_DL_DWARFMAP_H_

#include <libdwarf/dwarf.h>
#include <libdwarf/libdwarf.h>
#include <stdint.h>
#include <cstdint>
#include <gtirb/gtirb.hpp>
#include <map>
#include "AuxDataSchema.h"

class DwarfData
{
public:
    DwarfData(uint64_t addr, const char* name, Dwarf_Half tag, Dwarf_Unsigned file_no,
              Dwarf_Unsigned line_no);
    ~DwarfData() = default;

private:
    uint64_t addr;
    std::string name;
    Dwarf_Half tag;
    Dwarf_Unsigned file_no;
    Dwarf_Unsigned line_no;
};

class DwarfMap
{
private:
    int dwarf_fd;
    Dwarf_Error error;
    Dwarf_Debug debug;
    Dwarf_Handler handler;
    Dwarf_Ptr error_argument;
    std::map<uint64_t, DwarfData> dwarfdata;
    void traverse_compilation_units();
    void traverse(Dwarf_Die, int);
    void retrieve_die_data(Dwarf_Die);

public:
    DwarfMap(const std::string& filename);
    ~DwarfMap();
    void extract_dwarf_data();
    void flag_constsym(gtirb::Module& module);
};

#endif
