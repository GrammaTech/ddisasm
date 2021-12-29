//===- ArchiveReader.cpp ----------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2019-2022 GrammaTech, Inc.
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

#include "./ArchiveReader.h"

#include <algorithm>
#include <cstring>
#include <iostream>

const std::vector<uint8_t> ar_magic = {'!', '<', 'a', 'r', 'c', 'h', '>', '\n'};

bool ArchiveReader::is_ar(const std::string &Path)
{
    std::ifstream Stream;
    Stream.open(Path, std::ios::in | std::ios::binary);

    return ArchiveReader::is_ar(Stream);
}

bool ArchiveReader::is_ar(std::ifstream &Stream)
{
    std::vector<uint8_t> buf;
    buf.resize(ar_magic.size());

    Stream.read(reinterpret_cast<char *>(buf.data()), buf.size());
    return buf == ar_magic;
}

ArchiveReader::ArchiveReader(const std::string &P) : Path(P)
{
    Stream.open(Path, std::ios::in | std::ios::binary);
    Stream.seekg(0, Stream.end);
    uint64_t Length = Stream.tellg();
    Stream.seekg(0, Stream.beg);

    if(!ArchiveReader::is_ar(Stream))
    {
        // TODO: error
    }

    uint64_t Offset = Stream.tellg();
    while(Offset < Length)
    {
        FileHeader Header;
        Stream.read(reinterpret_cast<char *>(&Header), sizeof(Header));
        Offset += sizeof(Header);

        if(std::memcmp(Header.end, "`\n", sizeof(Header.end)) != 0)
        {
            // TODO: this is an error!
        }

        auto File = std::make_shared<ArchiveReaderFile>(*this, Header, Offset);

        if(File->Ident.at(0) != '/')
        {
            _Files.push_back(File);
        }

        uint64_t SeekSize = File->Size;
        if(SeekSize % 2 != 0)
        {
            // File headers are aligned to even bytes
            // (i.e., the content is padded with "\n") if it has an odd size.
            SeekSize += 1;
        }

        Stream.seekg(SeekSize, Stream.cur);
        Offset += SeekSize;
    }
}

const std::list<std::shared_ptr<ArchiveReaderFile>> &ArchiveReader::Files()
{
    return _Files;
}

ArchiveReaderFile::ArchiveReaderFile(ArchiveReader &R, const FileHeader &Header, uint64_t O)
    : Reader(R),
      Ident(Header.ident, sizeof(Header.ident)),
      Size(std::stoull(std::string(Header.size, sizeof(Header.size)).c_str())),
      Offset(O)
{
    unsigned int index = Ident.find("/"); // sysv / GNU
    if(index == std::string::npos)
    {
        index = Ident.find(" "); // BSD
    }

    // TODO: support sysv / GNU extended filenames "/<offset>"
    // TODO: support 4.4BSD with #1/<length> Ident strings.

    FileName = Ident.substr(0, index);
}

void ArchiveReaderFile::Extract(const std::string &Path)
{
    Reader.Stream.seekg(Offset, Reader.Stream.beg);

    std::ofstream OStream;
    OStream.open(Path, std::ios::out | std::ios::binary);

    std::copy_n(std::istreambuf_iterator<char>(Reader.Stream), Size,
                std::ostreambuf_iterator<char>(OStream));
}
