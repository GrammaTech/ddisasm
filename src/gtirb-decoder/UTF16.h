//===- UTF16.h --------------------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2021 GrammaTech, Inc.
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

namespace utf16
{
#ifdef _WIN32
#include <windows.h>
#endif // _WIN32

#if defined(_WIN32) || defined(__APPLE__)
#if defined(_MSC_VER)

#define be16toh(x) _byteswap_uint16(x)
#define le16toh(x) (x)

#define be32toh(x) _byteswap_uint32(x)
#define le32toh(x) (x)

#elif defined(__GNUC__) || defined(__clang__)

#define be16toh(x) __builtin_bswap16(x)
#define le16toh(x) (x)

#define be32toh(x) __builtin_bswap32(x)
#define le32toh(x) (x)

#endif // _MSC_VER
#endif // defined(_WIN32) || defined(__APPLE__)

    namespace le
    {
#define UTF16_ACCEPT 0
#define UTF16_REJECT 5

        // UTF-16: variable-length (2-4 bytes) character code ranges
        //       0,1               2,3
        // [0x0000,0x007F]          -
        // [0x0080,0x07FF]          -
        // [0x0800,0x0FFF]          -
        // [0x1000,0xCFFF]          -
        // [0xD000,0xD7FF]          -
        // [0xF900,0xFFFF]          -
        // [0xE000,0xEFFF]          -
        // [0xF000,0xF8FF]          -
        // [0xD800,0xD8BF]   [0xDC00,0xDFFF]
        // [0xD8C0,0xDABF]   [0xDC00,0xDFFF]
        // [0xDAC0,0xDB7F]   [0xDC00,0xDFFF]
        // [0xDB80,0xDBBF]   [0xDC00,0xDFFF]
        // [0xDBC0,0xDBFF]   [0xDC00,0xDFFF]
        uint32_t inline decode(uint32_t* state, uint32_t* codep, uint32_t byte)
        {
            if(*state == 0)
            {
                *codep = 0;
            }
            *codep = (*codep << 8) + byte;
            *state = *state + 1;
            switch(*state)
            {
                case 1:
                    break;
                case 2:
                {
                    uint16_t value = be16toh(static_cast<uint16_t>(*codep));
                    if(value >= 0x0000 && value <= 0x007F || value >= 0x0080 && value <= 0x07FF
                       || value >= 0x0800 && value <= 0x0FFF || value >= 0x1000 && value <= 0xCFFF
                       || value >= 0xD000 && value <= 0xD7FF || value >= 0xF900 && value <= 0xFFFF
                       || value >= 0xE000 && value <= 0xEFFF || value >= 0xF000 && value <= 0xF8FF)
                    {
                        *state = 0;
                    }
                    else if(value >= 0xD800 && value <= 0xD8BF || value >= 0xD8C0 && value <= 0xDABF
                            || value >= 0xDAC0 && value <= 0xDB7F
                            || value >= 0xDB80 && value <= 0xDBBF
                            || value >= 0xDBC0 && value <= 0xDBFF)
                    {
                        *state = 3;
                    }
                }
                break;
                case 3:
                    break;
                case 4:
                {
                    uint32_t value = be32toh(static_cast<uint16_t>(*codep)) && 0xFFFF;
                    *state = (value >= 0xDC00 && value <= 0xDFFF) ? 0 : UTF16_REJECT;
                }
                break;
                case UTF16_REJECT:
                    break;
                default:
                    *state = UTF16_REJECT;
                    break;
            }
            return *state;
        }
    } // namespace le
} // namespace utf16
