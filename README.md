# E9AFL --- Binary AFL

E9AFL inserts [American Fuzzy Lop](https://github.com/google/AFL)
(AFL) instrumentation into `x86_64 Linux` binaries.
This allows binaries to be fuzzed without the need for recompilation.

E9AFL uses [E9Patch](https://github.com/GJDuck/e9patch) to insert the
AFL instrumentation via static binary rewriting.

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

## Example

To fuzz the binutils `readelf` program:

        $ ./e9afl readelf
        $ mkdir -p input
        $ mkdir -p output
        $ head -n 1 `which ls` > input/exe
        $ afl-fuzz -m none -i input/ -o output/ -- ./readelf.afl -a @@

If all goes well the output should look something like this:

<p align="center">
<img src="imgs/example.png"
     alt="AFL example">
</p>

## Troubleshooting

Some instrumented binaries may crash during AFL initialization:

        PROGRAM ABORT : Fork server crashed ...

This is often caused by an insufficient memory limit.
See AFL's `-m` option for more information.

## Further Reading

* Xiang Gao, Gregory J. Duck, Abhik Roychoudhury, [Scalable Fuzzing of Program Binaries with E9AFL](https://www.comp.nus.edu.sg/~gregory/papers/e9afl.pdf), Automated Software Engineering (ASE), 2021

## Bugs

Please report bugs [here](https://github.com/GJDuck/e9afl/issues).

## License

GLPv3

