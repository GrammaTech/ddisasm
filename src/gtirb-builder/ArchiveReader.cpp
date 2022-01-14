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
#include <unordered_map>

const std::vector<uint8_t> ArMagic = {'!', '<', 'a', 'r', 'c', 'h', '>', '\n'};
const std::string SymdefPrefix = "__.SYMDEF";

bool ArchiveReader::isAr(const std::string &Path)
{
    std::ifstream Stream(Path, std::ios::in | std::ios::binary);
    return ArchiveReader::isAr(Stream);
}

bool ArchiveReader::isAr(std::ifstream &Stream)
{
    std::vector<uint8_t> buf;
    buf.resize(ArMagic.size());

    Stream.read(reinterpret_cast<char *>(buf.data()), buf.size());
    return buf == ArMagic;
}

ArchiveReader::ArchiveReader(const std::string &P)
    : Path(P), Stream(Path, std::ios::in | std::ios::binary)
{
    Stream.seekg(0, Stream.end);
    uint64_t Length = Stream.tellg();
    Stream.seekg(0, Stream.beg);

    std::unordered_map<uint64_t, std::string> GnuExtendedFilenames;

    if(!ArchiveReader::isAr(Stream))
    {
        throw ArchiveReaderException("Invalid ar format: unexpected magic");
    }

    uint64_t Offset = Stream.tellg();
    while(Offset < Length)
    {
        FileHeader Header;
        Stream.read(reinterpret_cast<char *>(&Header), sizeof(Header));
        Offset += sizeof(Header);

        if(std::memcmp(Header.end, "`\n", sizeof(Header.end)) != 0)
        {
            throw ArchiveReaderException("Invalid ar format: unexpected terminator");
        }

        ArchiveReaderFile File = ArchiveReaderFile(Header, Offset);

        // Handle special files: extended filename table and symbol table.
        // These are expected to be the first entries in the archive, before
        // any regular files are seen.
        if(File.FileNameFormat == Unextended
           && (File.FileName == "/" || File.FileName == "ARFILENAMES/"))
        {
            // GNU extended filenames entry
            size_t LineOffset = 0;
            while(LineOffset < File.Size)
            {
                std::string Line(File.Size - LineOffset + 1, '\0');
                Stream.getline(Line.data(), Line.size() - 1, '\n');
                size_t LineSize = Line.find_first_of('\0');
                Line.resize(LineSize);

                // Remove trailing "/" from the filename
                if(Line[LineSize - 1] == '/')
                {
                    Line.erase(LineSize - 1);
                }

                if(Line != "")
                {
                    GnuExtendedFilenames.insert({LineOffset, Line});
                }

                LineOffset += LineSize + 1;
            }
        }
        else if(File.FileNameFormat == Unextended
                && (File.FileName == ""
                    || File.FileName.compare(0, SymdefPrefix.size(), SymdefPrefix) == 0))
        {
            // symtable entry: ignore.
        }
        else
        {
            // Expand extended file names, if needed.
            if(File.FileNameFormat == GNUExtended)
            {
                auto FileNameIt = GnuExtendedFilenames.find(File.ExtendedFileNameNumber);

                if(FileNameIt == GnuExtendedFilenames.end())
                {
                    throw ArchiveReaderException("Invalid ar format: extended filename not found");
                }
                File.FileName = FileNameIt->second;
            }
            else if(File.FileNameFormat == BSDExtended)
            {
                File.FileName.resize(File.ExtendedFileNameNumber);
                Stream.read(File.FileName.data(), File.ExtendedFileNameNumber);
                Offset += File.ExtendedFileNameNumber;

                if(File.ExtendedFileNameNumber > File.Size)
                {
                    throw ArchiveReaderException("Invalid ar format: extended file name too long");
                }
                File.Offset += File.ExtendedFileNameNumber;
                File.Size -= File.ExtendedFileNameNumber;
            }

            Files.push_back(File);
        }

        Offset += File.Size;
        if(Offset % 2 != 0)
        {
            // File headers are aligned to even bytes
            // (i.e., the content is padded with "\n") if it has an odd size.
            Offset += 1;
        }
        Stream.seekg(Offset, Stream.beg);
    }
}

void ArchiveReader::ReadFile(ArchiveReaderFile &File, std::vector<uint8_t> &Data)
{
    Stream.seekg(File.Offset, Stream.beg);
    Data.resize(File.Size);
    std::copy_n(std::istreambuf_iterator<char>(Stream), File.Size, Data.begin());
}

ArchiveReaderFile::ArchiveReaderFile(const FileHeader &Header, uint64_t O)
    : Ident(Header.ident, sizeof(Header.ident)),
      Size(std::stoull(std::string(Header.size, sizeof(Header.size)).c_str())),
      Offset(O),
      FileNameFormat(Unextended),
      ExtendedFileNameNumber(0)
{
    // We support file name formats supported by binutils, see:
    // https://sourceware.org/git/?p=binutils-gdb.git;a=blob;f=bfd/archive.c;h=9ad61adc6159a2731a0443353f393baeea48bf5d#l85
    size_t Index = Ident.find_last_of("/");
    if(Index == std::string::npos)
    {
        // There are no "/". BSD variant uses space as the delimiter, and
        // forbids spaces in names.
        Index = Ident.find_first_of(" ");
    }

    if(Index != std::string::npos)
    {
        if(Ident[Index] == '/' && Ident.compare(0, Index, "#1") == 0)
        {
            // BSD 4.4 extended filename format: "#1/<length>", filename at start of data.
            FileNameFormat = BSDExtended;
        }
        else if(Index == 0)
        {
            // SysV/GNU extended format: "/<offset>", offset into ar entry with Ident "//".
            // "pseudo-BSD" format (as binutils calls it): " <offset>"
            FileNameFormat = GNUExtended;
        }

        if(FileNameFormat != Unextended)
        {
            size_t FirstNonNumChar = Ident.find_last_of("0123456789") + 1;

            if(FirstNonNumChar > Index)
            {
                ExtendedFileNameNumber = std::stoull(Ident.substr(Index + 1, FirstNonNumChar));

                // Verify: all trailing characters should be spaces.
                if(Ident.find_first_not_of(" ", FirstNonNumChar) != std::string::npos)
                {
                    throw ArchiveReaderException("Invalid ar format: unexpected file name format");
                }
            }
            else
            {
                // No trailing number. It must be a unextended FileName after all.
                FileNameFormat = Unextended;
            }
        }
    }

    // Fallthrough: nothing else worked, it's just a normal filename.
    if(FileNameFormat == Unextended)
    {
        FileName = Ident.substr(0, Index);
    }
}
