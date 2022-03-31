//===- Functors.h -----------------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2022 GrammaTech, Inc.
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
#ifndef SRC_FUNCTORS_H_
#define SRC_FUNCTORS_H_
#include <gtirb/gtirb.hpp>

// C interface is used for accessing the functors from datalog
extern "C"
{
    __attribute__((__visibility__("default"))) uint64_t functor_data_exists(uint64_t EA,
                                                                            size_t Size);
    __attribute__((__visibility__("default"))) uint64_t functor_data_u8(uint64_t EA);

    __attribute__((__visibility__("default"))) int64_t functor_data_s16(uint64_t EA);
    __attribute__((__visibility__("default"))) int64_t functor_data_s32(uint64_t EA);
    __attribute__((__visibility__("default"))) int64_t functor_data_s64(uint64_t EA);
}

// C++ interface allows ddisasm CPP code to instantiate functor data
void initFunctorGtirbModule(const gtirb::Module* M);

#endif // SRC_FUNCTORS_H_
