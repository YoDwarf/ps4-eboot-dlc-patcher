#!/bin/sh
set -e

# Store the current directory
original_dir=$(pwd)

# Change the working directory to the script's location
cd "$(dirname "$0")"

# Libraries to link in
libraries="-lc -lkernel -lSceSysmodule -lSceAppContent -lSceAppContentIro -lSceAppContentSc"

intdir=./temp
targetname=dlcldr
outputPath=$(pwd)/bin

outputElf="$intdir/$targetname.elf"
outputOelf="$intdir/$targetname.oelf"
outputPrx="$targetname.prx"
outputStub="${targetname}_stub.so"

[ ! -d "$intdir" ] && mkdir "$intdir"
[ ! -d "$outputPath" ] && mkdir "$outputPath"

cleanup_and_exit() {
    # Move files
    mv "$outputPrx" "$outputPath/$outputPrx" || true
    mv "$outputOelf" "$outputPath/${targetname}_unsigned.elf" || true

    rm "$outputStub" || true

    # Cleanup temp directory
    rm -dr "$intdir" || true

    # Restore the original directory
    cd "$original_dir" || exit
    exit 1
}

# Compile object files for all the source files
for f in *.c; do
    [ -e "$f" ] || continue
    clang --target=x86_64-pc-freebsd12-elf -fPIC -funwind-tables -I"$OO_PS4_TOOLCHAIN/include" $extra_flags -c -o "$intdir/$(basename "$f" .c).o" "$f" || {
        echo "Error: Compilation failed for $f"
        cleanup_and_exit
    }
done

for f in *.cpp; do
    [ -e "$f" ] || continue
    clang++ --target=x86_64-pc-freebsd12-elf -fPIC -funwind-tables -I"$OO_PS4_TOOLCHAIN/include" -I"$OO_PS4_TOOLCHAIN/include/c++/v1" $extra_flags -c -o "$intdir/$(basename "$f" .cpp).o" "$f" || {
        echo "Error: Compilation failed for $f"
        cleanup_and_exit
    }
done

for f in *.s; do
    [ -e "$f" ] || continue
    clang --target=x86_64-pc-freebsd12-elf -mllvm -x86-asm-syntax=intel -fPIC -funwind-tables -I"$OO_PS4_TOOLCHAIN/include" $extra_flags -c -o "$intdir/$(basename "$f" .s).o" "$f" || {
        echo "Error: Compilation failed for $f"
        cleanup_and_exit
    }
done

# Get a list of object files for linking
obj_files=$(find "$intdir" -name '*.o' | tr '\n' ' ')

# Link the input ELF
ld.lld -m elf_x86_64 -pie --script "$OO_PS4_TOOLCHAIN/link.x" --eh-frame-hdr -o "$outputElf" "-L$OO_PS4_TOOLCHAIN/lib" $libraries --verbose -e "module_start" $obj_files || {
    echo "Error: Linking failed."
    cleanup_and_exit
}

# Create stub shared libraries
for f in *.c; do
    [ -e "$f" ] || continue
    clang -target x86_64-pc-linux-gnu -ffreestanding -nostdlib -fno-builtin -fPIC -c -I"$OO_PS4_TOOLCHAIN/include" -o "$intdir/$(basename "$f" .c).o.stub" "$f" || {
        echo "Error: Stub Compilation failed for $f"
        cleanup_and_exit
    }
done

for f in *.cpp; do
    [ -e "$f" ] || continue
    clang++ -target x86_64-pc-linux-gnu -ffreestanding -nostdlib -fno-builtin -fPIC -c -I"$OO_PS4_TOOLCHAIN/include" -I"$OO_PS4_TOOLCHAIN/include/c++/v1" -o "$intdir/$(basename "$f" .cpp).o.stub" "$f" || {
        echo "Error: Stub Compilation failed for $f"
        cleanup_and_exit
    }
done

stub_obj_files=$(find "$intdir" -name '*.o.stub' | tr '\n' ' ')

clang++ -target x86_64-pc-linux-gnu -shared -fuse-ld=lld -ffreestanding -nostdlib -fno-builtin "-L$OO_PS4_TOOLCHAIN/lib" $libraries $stub_obj_files -o "$outputStub" || {
    echo "Error: Creating stub shared library failed."
    cleanup_and_exit
}

# Create the prx
$OO_PS4_TOOLCHAIN/bin/linux/create-fself -in "$outputElf" --out "$outputOelf" --lib "$outputPrx" --libname "$targetname" --paid 0x3800000000000011 || {
    echo "Error: Creating PRX failed."
    cleanup_and_exit
}

cleanup_and_exit