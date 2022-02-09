//===- ArchiveReader.h ------------------------------------------*- C++ -*-===//
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

#ifndef ARCHIVE_READER_H_
#define ARCHIVE_READER_H_

#include <exception>
#include <fstream>
#include <list>
#include <memory>
#include <string>
#include <vector>

class ArchiveReaderException : public std::exception
{
    std::string error_message;

public:
    ArchiveReaderException(const std::string &msg) : error_message(msg)
    {
    }

    virtual const char *what() const throw()
    {
        return error_message.c_str();
    }
};

class ArchiveReaderFile
{
public:
    struct EntryHeader
    {
        char ident[16]; // file identifier (ascii)
        char ts[12];    // modification timestamp (decimal)
        char oid[6];    // owner id (decimal)
        char gid[6];    // group id (decimal)
        char mode[8];   // file mode (octal)
        char size[10];  // file size in bytes (decimal)
        char end[2];    // terminator "`\n"
    };

    enum EntryFileNameFormat
    {
        Unextended,
        GNUExtended,
        BSDExtended
    };

    static ArchiveReaderFile build(const EntryHeader &Header, uint64_t O);

    EntryFileNameFormat FileNameFormat;
    uint64_t ExtendedFileNameNumber;
    std::string Ident;
    std::string FileName;
    uint64_t Size;
    uint64_t Offset;

private:
    ArchiveReaderFile(const EntryHeader &Header, uint64_t O);
    void build(void);
};

class ArchiveReader
{
public:
    static ArchiveReader read(const std::string &Path);
    void readFile(ArchiveReaderFile &File, std::vector<uint8_t> &Data);
    std::list<ArchiveReaderFile> Files;

    static bool isAr(const std::string &Path);

    /**
     * Determine if a stream is positioned at the start of an archive file.
     *
     * This function is NOT idempotent and may advance the stream position.
     * If the stream does contain an archive file, the stream is positioned
     * after the archive magic ("!<arch>\n").
     */
    static bool isAr(std::ifstream &Stream);

protected:
    ArchiveReader(const std::string &Path)
        : Path(Path), Stream(Path, std::ios::in | std::ios::binary)
    {
    }
    void read(void);
    std::string Path;
    std::ifstream Stream;
};

#endif // ARCHIVE_READER_H_
