SECTIONS
{
    xref_array :
    {
        *(xref_array)
    }
}
INSERT BEFORE .data;

SECTIONS
{
    extra_data :
    {
        *(extra_data)
    }
}
INSERT AFTER .data;
