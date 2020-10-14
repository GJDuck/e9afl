# E9AFL --- Binary AFL

E9AFL inserts [American Fuzzy Lop](https://github.com/google/AFL)
(AFL) instrumentation into `x86_64 Linux` binaries.
This allows binaries to be fuzzed without the need for recompilation.

E9AFL uses [E9Patch](https://github.com/GJDuck/e9patch) to insert the
AFL instrumentation using static binary rewriting.

## Building

To build E9AFL, simply run the `build.sh` script:

        $ ./build.sh

## Usage

First, install `afl-fuzz`:

        $ sudo apt-get install afl

To use E9AFL, simply run the command:

        $ ./e9afl /path/to/binary

This will generate an AFL-instrumented `binary.afl` which can be
used with `afl-fuzz`.
See the example below.

Note that E9Patch uses a lot of virtual address space, so typically
`afl-fuzz` should be run with a suitably high memory limit.
See the `-m` option for `afl-fuzz`

## Example

To fuzz the binutils `readelf` program:

        $ ./e9afl readelf
        $ mkdir -p input
        $ mkdir -p output
        $ head -n 1 `which ls` > input/exe
        $ afl-fuzz -m 500000000 -i input/ -o output/ -- ./readelf.afl -a @@

If all goes well the output should look something like this:

<p align="center">
<img src="imgs/example.png"
     alt="AFL example">
</p>

## Limitations

E9AFL is a quick port that has not been well-tested.
Please report bugs [here](https://github.com/GJDuck/e9afl/issues).

E9AFL relies on a basic-block recovery analysis which is simple but
inaccurate for indirect jumps.
This means that some paths will not be visible to `afl-fuzz`.
E9Patch may fail to instrument some instructions, which may also result in 
missed paths.
However, for most binaries E9AFL should give reasonable performance.

E9AFL is based on [E9Patch](https://github.com/GJDuck/e9patch) which
uses a complex virtual address space layout for the instrumented binary.
This can slow down `fork()`, which limits the performance of
E9AFL-instrumented binaries (although it still seems faster than QEMU mode).
You can increase the performance (at the cost of file size) by
decreasing the compression-level using the `-c` option, e.g.:

        $ ./e9afl -c 1 readelf
 
## License

GLPv3

