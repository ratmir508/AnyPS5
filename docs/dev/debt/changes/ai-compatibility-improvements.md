# relinker

## change An `R_X86_64_GLOB_DAT` or `R_X86_64_JUMP_SLOT` relocation with a nonzero addend fails the conversion

- An `R_X86_64_GLOB_DAT` or `R_X86_64_JUMP_SLOT` relocation with a nonzero addend binds to S ([pipeline](../../../core/relinker/relinker/src/pipeline/RelinkerPipeline.cpp), [guest image reader](../../../core/relinker/relinker/src/guest/GuestImageReader.cpp)): the pipeline drops the addend from the emitted reference, one note counts the ignored addends of the executable, and the guest image reader zeroes the addend of the copied entry, so every output format computes S. The x86-64 psABI computes both as S, as glibc applies them since [f8587a61892c](https://github.com/bminor/glibc/commit/f8587a61892cbafd98ce599131bf4f103466f084) (2.36); FreeBSD rtld uses S for GLOB_DAT and lazy JUMP_SLOT and S+A for eager JUMP_SLOT, so what the console's loader does with such an addend is still not measured.
