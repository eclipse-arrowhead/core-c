# Eclipse Arrowhead™ Core C Libraries

This repository gathers C99 libraries officially developed by Eclipse
Arrowhead™. These libraries build on top of the C99 standard library to provide
cross-platform asynchronous I/O, support for various encodings and protocols, as
well as code directly dealing with the provision and consumption of Arrowhead™
services.

These libraries are designed to be deployable on both embedded and more capable
hardware. In case of the former, we expect a few hundred kilobytes of RAM and
ROM to be sufficient, while on more traditional servers and desktop computers,
a few megabytes of RAM and disk will likely be required.

At the time of writing, this repository is still quite new and, as a
consequence, unencumbered by any significant adoption. As a consequence, you are
likely to find bugs and other problems. We would love you to help mitigate or at
least report any such you find, as we direct further below.

## Repository Organization

The Eclipse Arrowhead™ Core C libraries are all located in `libraries` folder of
the [core-c][ghub] project of the official Arrowhead™ framework GitHub
repository. This folder contains this README file and configuration files at its
root. Additionally, it contains a number of folders whose name start with `ah_`.
Each of those folders contains its own Arrowhead™ library, complete with its own
documentation and build files. Some of these libraries depend on others, while
others can be used in isolation. In the few cases where they depend on 3rd party
libraries, it is carefully documented. Most libraries depend on the `ah_base`
library, directly or indirectly, which provides cross-platform networking, error
management, and other similarly fundamental utilities.

[ghub]: https://github.com/eclipse-arrowhead/core-c
[base]: ah_base/

## Building and Installing

All official libraries are built and installed using [CMake][cmak]. Please refer
to the [defs.h][defs] file in the `ah_base` library for more details about
supported compilers and platforms.

[cmak]: https://cmake.org/
[defs]: ah_base/include/ah/defs.h

## Contributing

We welcome GitHub pull requests and other code contributions from everyone who
agrees to sign the [Eclipse Contributor Agreement (ECA)][ecag]. If you wish to
report bugs you found, or discuss other improvements to these libraries, please
do so by [creating a GitHub issue][ghis]. You do not need to sign the ECA to
write GitHub issues.

[ecag]: https://www.eclipse.org/legal/ECA.php
[ghis]: https://github.com/eclipse-arrowhead/core-c/issues

If you do contribute code, please observe the following:

1. Larger additions or changes should be discussed in advance of them being 
   written by them being announced in [GitHub issues][ghis] you create, or we
   may end up being unable to accept your contribution.
2. We expect the code you write to follow the same style and conventions used in
   the already existing libraries. While we do not have an official conventions
   guide at the moment, using the `ah_base` library as guide and making sure to
   use our [clang-format][claf] profile for automatic formatting
   should bring you close enough.
3. All data structures, functions and other globals you modify or create must be
   adequately documented. The documentation must be compatible with
   [Doxygen][dxyg] and must follow the Javadoc pattern already used in the
   existing libraries.

[claf]: https://clang.llvm.org/docs/ClangFormat.html
[dxyg]: https://doxygen.org