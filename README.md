# TPM NV Space Access Tool (`tpmtool`)
The `TpmTool` utility is a cross-platform tool for accessing `TPM2.0` Non-Volatile (NV) Spaces (Index Values) on compliant systems. It provides the ability to enumerate, create, delete, query, and lock NV indices, as well as to read and write data stored in them.

# Features
* Enumerate all `TPM2.0` handles that map to NV index values.
* Query a particular NV index value to get back its size, attributes, permissions, and dirty (_written_) flag.
* Create a new NV index of up to the architecturally maximum supported size, with an optional password authorization. The following attributes are supported
** Making the index support being locked against read and/or write access until the next reset.
** Making the index support being write-once once locked, regardless of reset.
** Making the index write-all such that all data must be written in one go, starting at offset `0`.
** Making the index store its data in RAM, and only written to NV storage during orderly shutdown.
** Making the index's dirty (_written_) flag volatile, i.e.: cleared at the next reset.
** Making the index non-deleteable except through special policy. Note that `tpmtool` does not support this type of deletion, however.
** Making the indedx unprotected against dictionary attacks, and ignore the lockout if one was reached.
* Delete an existing NV index, as long as authorization is valid and the index does not require policy-based deletion (see above).
* Read the data stored in an NV index, both as a hexdump in `STDERR` for visual rendering, as well as raw data in `STDOUT`, which can be redirected to a file.
* Write data to be stored in an NV index, based on `STDIN`, which can either be piped through `echo` or redirected from a file.
* Lock an NV index either against further reads, and/or against further writes, until the next `TPM2.0` reset. The index must have been created with the appropriate attributes to allow read and/or write locking, and further, if it was created as write-once, then it can only be deleted and re-created. 

# Requirements
For Windows, you must have a valid `TPM2.0` chip and Windows `8` or later, which is the first version where support for `TPM2.0` was added to the TPM Base Services (TBS). For Linux, you must have a valid `TPM2.0` chip and a Linux Kernel which supports the TPM Arbiter Service (`TPMAS`) either natively or through a 3rd party daemon. Either way, it must be accessible through `/dev/tpmrm0`.

On Windows, you must run `TpmTool` with `Administrator` privileges and similarly, on Linux, with `root` privileges such as through usage of `sudo`.

# Examples

# Full Usage Help
```
TpmTool v1.0.0 - Access TPM2.0 NV Spaces
Copyright (C) 2020 Alex Ionescu
@aionescu -- www.windows-internals.com

TpmTool allows you to define non-volatile (NV) spaces (indices) and
read/write data within them. Password authentication can optionally
be used to protect their contents.

Usage: tpmtool [-e|index]
               [-c <attributes> <owner> <auth> <size>|-r <offset> <size>|-w <offset> <size>|-rl|-wl|-d|-q]
               [password]
    -e    Enumerates all NV spaces active on the TPM
    -c    Create a new NV space with the given index value.
          Attributes can be a combination (use + for multiple) of:
              RL    Allow the resulting NV index to be read-locked.
              WL    Allow the resulting NV index to be write-locked.
              WO    Make the write-locked state of the NV index permanent.
              WA    Partial writes are not allowed into the NV index.
              NP    No protection against dictionary attacks.
              CH    Cache the resulting NV index in RAM (orderly).
              VL    Makes the dirty flag volatile (cleared at startup).
              PT    Marks the NV space as non-deletable without a policy.
          Owner and Auth rights can be one of R, RW, or NA.
          Size is limited by TPM should usually be 2048 or less.
    -r    Read the data stored at the given index value.
          Offset and size must be fit within size of the space.
          Data is printed to STDOUT and can be redirected to a file.
    -w    Write the data from STDIN into the given index value.
          Offset and size must be fit within size of the space.
          You can use pipes or redirection to write from a file.
    -q    Query the size, rights, and attributes of the given index.
          Also indicates if the index has ever been written to (dirty).
          Attributes are the same as shown earlier, with the addition of:
              LR    The index is locked against reads until reset.
              LW    The index is locked against writes until reset.
                    NOTE: If the WO attribute is set, locked forever.
              PO    The index was created and is owned by the platform.
    -rl   Lock the NV space at the given index value against reads.
          The NV space must have been created with the RL attribute.
    -wl   Lock the NV space at the given index value against writes.
          The NV space must have been created with the WL attribute.
    -d    Delete the NV space at the given index value.

If the index was created with a password and owner auth is NA, the
password must be used on any further read or write operations.
