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

struct FileHeader
{
    char ident[16]; // file identifier (ascii)
    char ts[12];    // modificiation timestamp (decimal)
    char oid[6];    // owner id (decimal)
    char gid[6];    // group id (decimal)
    char mode[8];   // file mode (octal)
    char size[10];  // file size in bytes (decimal)
    char end[2];    // terminator "`\n"
};

enum ArchiveReaderFilenameFormat
{
    Unextended,
    GNUExtended,
    BSDExtended
};

class ArchiveReader;
class ArchiveReaderFile
{
public:
    ArchiveReaderFile(ArchiveReader &R, const FileHeader &Header, uint64_t O);
    void Extract(const std::string &Path);

    ArchiveReader &Reader;
    ArchiveReaderFilenameFormat FileNameFormat;
    uint64_t ExtendedFileNameNumber;
    std::string Ident;
    std::string FileName;
    uint64_t Size;
    uint64_t Offset;
};

class ArchiveReader
{
public:
    ArchiveReader(const std::string &Path);
    const std::list<std::shared_ptr<ArchiveReaderFile>> &Files();

    static bool is_ar(const std::string &Path);
    static bool is_ar(std::ifstream &Stream);

protected:
    std::list<std::shared_ptr<ArchiveReaderFile>> _Files;
    std::string Path;
    std::ifstream Stream;

    friend class ArchiveReaderFile;
};

#endif // ARCHIVE_READER_H_
