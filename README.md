# tpmtool
TpmTool is a cross-platform tool for accessing TPM Non-Volatile (NV) Spaces (Index Values)

# Usage
```
TpmTool v1.0.0 - Access TPM2.0 NV Spaces
Copyright (C) 2020 Alex Ionescu
@aionescu -- www.windows-internals.com

TpmTool allows you to define non-volatile (NV) spaces (indices) and
read/write data within them. Password authentication can optionally
be used to protect their contents.

Usage: tpmtool [-e|index] [-c <attributes> <owner> <auth> <size>|-r <offset> <size>|-w <offset> <size>|-rl|-wl|-d|-q] [password]
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
