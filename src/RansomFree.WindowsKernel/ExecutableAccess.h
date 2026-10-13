#pragma once
// Pure predicates shared by the qualification driver and native regression test.
// Candidate selection is not an access grant. Generic mapping and successful
// CREATE completion must precede any data-read admission.
static __inline BOOLEAN SqExecutableCandidateAccess(ACCESS_MASK requested)
{
    return (requested & (FILE_EXECUTE | GENERIC_EXECUTE | GENERIC_ALL)) != 0;
}
static __inline BOOLEAN SqExecutableMappedAccess(ACCESS_MASK mapped)
{
    return (mapped & (FILE_READ_DATA | FILE_EXECUTE)) == (FILE_READ_DATA | FILE_EXECUTE) &&
        (mapped & (MAXIMUM_ALLOWED | GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL)) == 0;
}
