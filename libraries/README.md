# Eclipse Arrowhead™ Core C Libraries

This repository gathers C99 libraries officially developed by the Eclipse
Arrowhead project. These libraries build on top of the C99 standard library to
provide cross-platform asynchronous I/O, support for various encodings and
protocols, as  well as code directly dealing with the provision and consumption
of Arrowhead services.

These libraries are designed to be deployable on both embedded and more capable
hardware. In case of the former, we expect a few hundred kilobytes of RAM and
ROM/flash to be sufficient, while on more traditional servers and desktop
computers, we expect at least hundreds of megabytes of RAM to be available and
even more disk.

At the time of writing, this repository is still quite new and unencumbered by
significant adoption. As a consequence, you are likely to find bugs and other
problems as you evaluate and deploy these libraries. We would love you to help
report and mitigate any such issues you may find. A brief description of how to
go about to provide us with such help is given at the bottom of this page.

## Repository Organization

The Eclipse Arrowhead Core C libraries are all located in `libraries` folder of
the [core-c][ghub] project of the official Arrowhead framework
[GitHub organization][gorg]. folder contains this README file and configuration
files at its root. Additionally, it contains a number of folders whose name
start with `ah_`. Each of those folders contains its own Arrowhead library,
complete with its own documentation and build files. Some of these libraries
depend on each other, while others can be used in isolation. In the few cases
where they depend on 3rd party libraries, it should be clearly documented. Most
libraries depend on the `ah_base` library, directly or indirectly, which
provides cross-platform networking, error management, and other similarly
fundamental utilities.

[ghub]: https://github.com/eclipse-arrowhead/core-c
[gorg]: https://github.com/eclipse-arrowhead

## Building and Installing

All official libraries are built and installed using [CMake][cmak]. Each library
we provide is designed to be _linked statically_.

## Platform and Compiler Support

We currently support the following platforms and compilers:

[cmak]: https://cmake.org/

| Platform       | Supported versions        | Supported Compilers |
|:---------------|---------------------------|:--------------------|
| [Darwin][darw] | 16.0 and later*           | Clang, GCC          |
| [Linux][linu]  | Kernel 5.15 LTS and later | Clang, GCC          |
| [Win32][wind]  | Windows 10 and later      | MSVC                |

*These versions of Darwin are used by macOS v10.12.0 and later, as well as by
 iOS 10.0.1 and later.

[darw]: https://github.com/apple/darwin-xnu
[linu]: https://www.kernel.org/
[wind]: https://docs.microsoft.com/en-us/windows/win32/api/

| Compiler       | Supported versions |
|:---------------|:-------------------|
| [Clang][clan]  | 13.0 and later     |
| [GCC][gcco]    | 9.0 and later      |
| [MSVC++][msvc] | 14.30 and later*   |

*These versions of MSVC++ are provided by Microsoft Visual Studio version 17.0
 and later.

[clan]: https://clang.llvm.org/
[gcco]: https://gcc.gnu.org/
[msvc]: https://visualstudio.microsoft.com/

Only CPU architectures with two's complement signed integer operations are
supported. This includes virtually all modern CPU architectures, including x86,
ARM, RISC-V, MIPS, and so on.

## Versioning

Libraries are versioned using a `MAJOR.MINOR.PATCH` schema. Each out of `MAJOR`,
`MINOR` and `PATCH` is a non-negative integer. When a library is first created,
its version is `0.0.0`. The three version integers are incremented as follows:

- `MAJOR` is incremented every time a _breaking API change_ is introduced, such
  as when changing the signature of a function, or moving or removing a field
  from a struct;
- `MINOR` is incremented whenever a _non-breaking API change_ is made; such as
  when adding a new function or adding a field to the end of a struct; while
- `PATCH` is incremented when the source code is updated without the API being
  changed, such as when fixing a bug, updating documentation or modifying
  _internal_ structs, functions or other globals.

If `MAJOR` is incremented, both `MINOR` and `PATCH` are reset to `0`. If `MINOR`
is incremented, only `PATCH` is reset to `0`.

One exception to the above rules applies to _unreleased_ libraries, which is to
say that their developers are not ready to commit to API stability yet. In this
case, the `MAJOR` version remains `0` and also breaking changes lead to `MINOR`
being updated. Upon release, `MAJOR` is changed to `1` to reflect the commitment
of the Arrowhead project to keep the library's API stable over time.

Each library is versioned separately from all other libraries. If a library
depends on a particular [Arrowhead release][arel], that is declared as a
dependency rather than being reflected in the library's own version.

[arel]: https://projects.eclipse.org/projects/iot.arrowhead

### No ABI Versioning

As all libraries are designed to be linked only statically, even on platforms
where dynamic linking is possible, we do not provide any ABI stability
guarantees. Not even between patch versions of our libraries.

## Contributing

We welcome code contributions from everyone who agrees to sign the
[Eclipse Contributor Agreement (ECA)][ecag]. You are also very welcome to report
bugs, ask questions or discuss other topics of relevance by
[creating GitHub issues][ghis] in the official Core C GitHub repository.
Submitting GitHub issues does not require you to sign the ECA.

[ecag]: https://www.eclipse.org/legal/ECA.php
[ghis]: https://github.com/eclipse-arrowhead/core-c/issues

If you wish to contribute code, please observe the following:

1. Additions or other changes that break or add non-trivially to the APIs of our 
   libraries should be announced as [GitHub issues][ghis] (or be approved by the
   [Eclipse Leads or Commiters][lead] some other way), or we may end up being
   unable to accept your contribution.
2. We expect the code you write to follow the same style and coding conventions
   as are used in the already existing libraries. While we do not have an
   official guide at the moment, using the `ah_base` library as example and
   using our [clang-format][claf] profile for automatic formatting should bring
   your contribution close to an acceptable state.
3. All publicly facing data structures, functions and other globals you modify
   or create must be adequately documented. The documentation must be compatible
   with [Doxygen][dxyg] and must follow the Javadoc pattern already used in the
   existing libraries.
4. You must adhere to our versioning schema, described earlier in this document.
5. Your contribution must be submitted in the form of a GitHub pull request to
   the Eclipse Arrowhead [core-c][ghub] project repository.

[lead]: https://projects.eclipse.org/projects/iot.arrowhead/who
[claf]: https://clang.llvm.org/docs/ClangFormat.html
[dxyg]: https://doxygen.org