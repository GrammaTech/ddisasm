//============================================================================
// Name        : souffle_disasm.cpp
// Author      : Antonio Flores-Montoya
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================
#include "gtr/src/lang/gtr_config.h"
#include "gtr/src/string/tohex.hpp"
#include "isal/x64/decoderff.hpp"
#include "isal/x64/pprinter.hpp"

#include "souffle/SouffleInterface.h"

#include <cctype>
#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <limits>

typedef csuint64 ea_int_t;
//#define NBYTES_ON_FAILURE(buf) 1
//#define TO_ASM(instr) X64genPPrinter::to_asm(instr, mode)

//---------------------
// VSA_DLL_DEP HACK!!!
// <isa>_show depends on tsl_rtg_<isa>, which uses memcasecmp and should
// rightfully depend on feature 'string'.  However, the situation with Windows'
// vsa_tsl_<isa>.dll/swyxana_<isa>.lib currently prevents us from adding that
// dependence, as it leads to linker multiply-defined symbol errors.
// As a (very ugly) workaround, we add this dummy dependence on memcasecmp,
// with a corresponding dummy SCons dependence on 'string', to let this link
// successfully without changing tsl_rtg_<isa>'s dependences.
#include "gtr/src/string/string_ops.h"
int dummy_hack(const void * lhs, size_t lsize, const void * rhs, size_t rsize) {
	return memcasecmp(lhs, lsize, rhs, rsize);
}
// end VSA_DLL_DEP HACK

int main(int argc, char** argv) {
	if (argc < 2) {
		std::cerr << "Give me some argument" << std::endl;
		exit(1);
	}

	X64genDecoderFF::initialize();
	// initialize the first EA with the address argument, if provided
	ea_int_t ea = 0;
	if (argc >= 3 && !strncasecmp(argv[2], "-address=", 9))
		ea = strtoull(argv[2] + 9, 0, 0);

	std::filebuf fbuf;
	fbuf.open(argv[1], std::ios::in | std::ios::binary);
	size_t buf_size = 102400;
	char * buf = new char[buf_size];
	std::streamsize nbytes_left = fbuf.sgetn(buf, buf_size);
	char * bufptr = buf;

	while (nbytes_left > 0) {
		unsigned int nbytes_decoded;
		// safe to cast here since nbytes_left is in the range (0-buf_size]
		ConcTSLInterface::instructionRefPtr instr = X64genDecoderFF::decode(
				bufptr, ea, static_cast<unsigned int>(nbytes_left),
				&nbytes_decoded, IADC_LongMode);

		if (instr.is_empty()) {
			std::cout << "invalid("<<ea << ")"<<std::endl;
		} else {
			std::cout << instr << std::endl;
		}
		++ea;
		++bufptr;
		--nbytes_left;
		if (nbytes_left == 0) {
			nbytes_left = fbuf.sgetn(buf, buf_size);
			bufptr = buf;
		}
	}
	delete buf;
	return 0;
}



