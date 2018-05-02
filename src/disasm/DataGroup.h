#pragma once

#include <cstdint>
#include <string>

///
/// \class DisasmData
///
/// Port of the prolog disasm.
///
class DataGroup
{
public:
    enum class Type
    {
        LabelMarker,
        PLTReference,
        Pointer,
        PointerDiff,
        String,
        RawByte
    };

    DataGroup() = delete;

    DataGroup(uint64_t x) : ea(x)
    {
    }

    virtual ~DataGroup() = default;

    virtual DataGroup::Type getType() const = 0;

    inline void setEA(uint64_t x)
    {
        this->ea = x;
    }

    inline uint64_t getEA() const
    {
        return this->ea;
    }

private:
    uint64_t ea{0};
};

///
/// \class DataGroupLabelMarker
///
class DataGroupLabelMarker : public DataGroup
{
public:
    DataGroupLabelMarker(uint64_t x) : DataGroup(x)
    {
    }

    ~DataGroupLabelMarker() override = default;

    DataGroup::Type getType() const override
    {
        return DataGroup::Type::LabelMarker;
    }

private:
};

///
/// \class DataGroupPLTReference
///
class DataGroupPLTReference : public DataGroup
{
public:
    DataGroupPLTReference(uint64_t x) : DataGroup(x)
    {
    }

    ~DataGroupPLTReference() override = default;

    DataGroup::Type getType() const override
    {
        return DataGroup::Type::PLTReference;
    }

    std::string Function;

private:
};

///
/// \class DataGroupPointer
///
class DataGroupPointer : public DataGroup
{
public:
    DataGroupPointer(uint64_t x) : DataGroup(x)
    {
    }

    ~DataGroupPointer() override = default;

    DataGroup::Type getType() const override
    {
        return DataGroup::Type::Pointer;
    }

    uint64_t Content{0};

private:
};

///
/// \class DataGroupPointerDiff
///
class DataGroupPointerDiff : public DataGroup
{
public:
    DataGroupPointerDiff(uint64_t x) : DataGroup(x)
    {
    }

    ~DataGroupPointerDiff() override = default;

    DataGroup::Type getType() const override
    {
        return DataGroup::Type::PointerDiff;
    }

    uint64_t Symbol1{0};
    uint64_t Symbol2{0};

private:
};

///
/// \class DataGroupString
///
class DataGroupString : public DataGroup
{
public:
    DataGroupString(uint64_t x) : DataGroup(x)
    {
    }

    ~DataGroupString() override = default;

    DataGroup::Type getType() const override
    {
        return DataGroup::Type::String;
    }

    std::vector<uint8_t> StringBytes{};

private:
};

///
/// \class DataGroupRawByte
///
class DataGroupRawByte : public DataGroup
{
public:
    DataGroupRawByte(uint64_t x) : DataGroup(x)
    {
    }

    ~DataGroupRawByte() override = default;

    DataGroup::Type getType() const override
    {
        return DataGroup::Type::RawByte;
    }

    uint8_t Byte;

private:
};
