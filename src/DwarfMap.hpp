
#ifndef SRC_DL_DWARFMAP_H_
#define SRC_DL_DWARFMAP_H_

#include <libdwarf/dwarf.h>
#include <libdwarf/libdwarf.h>
#include <stdint.h>
#include <cstdlib>
#include <gtirb/gtirb.hpp>
#include <map>
#include "AuxDataSchema.h"

using namespace std;

class DwarfData
{
public:
    DwarfData(uint64_t addr, std::string* name, Dwarf_Half tag, Dwarf_Unsigned file_no,
              Dwarf_Unsigned line_no);
    ~DwarfData();

private:
    uint64_t addr;
    std::string* name;
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
    DwarfMap(const std::string filename);
    ~DwarfMap();
    std::map<uint64_t, DwarfData> dwarf_map();
    void extract_dwarf_data();
    void flag_constsym(gtirb::Module& module);
};

#endif
