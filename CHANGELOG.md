# Changes

## 0.7.2 - 2023-10-12

- Add `-z, --ziggy-output` flag and `ZIGGY_OUTPUT` environment variable to set ziggy's output directory
- Fix a couple of misbehaviours when building the fuzzers
- Improve populating of main corpus
- Add CI and tests
- Improve documentation

## 0.7.1 - 2023-10-05

- Fix honggfuzz bug
- Cleanup minimization logic
- Check grcov is installed before running coverage
- Fix CLI output glitches

## 0.7.0 - 2023-09-28

- Revamp CLI output
- Make honggfuzz learn from AFL++ seeds on the fly
- Remove initial minimization by default
- Fix bug with add-seeds secondary fuzzer name
- Improve AFL++ flags for more fuzzing diversity
- Add coverage feature to the harness
- Add casr triage functionality

## 0.6.8 - 2023-09-11

- Fix bug with add-seeds determinism
- Fix temporary corpus bug

## 0.6.7 - 2023-08-31

- Add new command - `cargo ziggy add-seeds`
- Tweak AFL++ flags for better performance
- Coverage now continues running after finding crash

## 0.6.6 - 2023-08-29

- Add CLI pointer to second AFL++ fuzzer log
- Update dependencies, including the new AFL++ crate

## 0.6.5 - 2023-08-24

- Secondary AFL++ fuzzer log is now available
- Bump AFL++ version
- Better AFL++ envs, thanks again @vanhauser-thc

## 0.6.4 - 2023-08-14

- Better AFL++ envs, thank you @vanhauser-thc!
- Bump AFL++ version
- Honggfuzz share of total CPUs is now reduced
- Overall code cleanup

## 0.6.3 - 2023-06-20

- Add flag to skip initial minimization

## 0.6.2 - 2023-06-20

- Fix parallel minimization bug

## 0.6.1 - 2023-06-20

- Add parallel jobs for minimization
- Add minimization at the beginning of fuzzing
- Fix crash discovery code

## 0.6.0 - 2023-06-07

- Remove no_main (pr #29, issue #28)
- Remove useless code

## 0.5.0 - 2023-06-07

- Update dependencies
- Fix coverage bug (see #27)
- Add better error handling and logs
- Split cargo-ziggy into different source files
- Remove statsd use for afl++
- Simplify console output while fuzzing
- Fix some long-standing fuzzer failure bugs

## 0.4.4 - 2023-04-25

- Fix error handling bug

## 0.4.3 - 2023-04-24

- Fix dependency bug

## 0.4.2 - 2023-04-24

- Fix honggfuzz interface not showing up in logs
- Fix some coverage generation difficulties (see #23)
- More verbose error handling (thanks @brunoproduit!)
- New default minimization timeout
- `--no-honggfuzz` and `--no-afl` flags
- Remove unused `init` command
- Fix inconsistent number of jobs (now `-j 4` will launch 4 threads, not 8)
- Update dependencies

## 0.4.1 - 2023-03-07

- Fix cargo ziggy run argument bug

## 0.4.0 - 2023-03-06

- Remove libfuzzer and add a custom runner
- Remove secondary afl logs
- Remove need to use rust nightly

## 0.3.4 - 2023-02-08

- Add -G and -g flags for max and min input sizes
- Add deterministic fuzzing to some AFL++ instances
- Update dependencies

## 0.3.3 - 2022-12-13

- Only run statsd on the main instance
- Fix small display bug

## 0.3.2 - 2022-12-01

- Fix crash directory bug

## 0.3.1 - 2022-11-30

- Fix CLI output bug

## 0.3.0 - 2022-11-29

- Add support for #[cfg(fuzzing)] and #[cfg(not(fuzzing))]
- Add warning for AFL++ kernel and CPU rules (#6)
- Change input corpus argument in the run subcommand
- Add source option for coverage generation (#8)
- Add crash aggregation directory (#3)
- Add variable to track if crashes were found (#10)
- Fix behaviour when user stops fuzzing in the middle of minimization (#7)
- Add `plot` subcommand using afl-plot (#5)
- Add initial corpus directory argument for fuzzing (#9)

## 0.2.3 - 2022-10-24

- Update dependencies (fixes yanked dependency issue)

## 0.2.2 - 2022-10-17

- Move logs to a `logs` directory (#4)
- Automatically select target if possible (#1)

## 0.2.1 - 2022-09-23

- Add reset_lazy static option support for better AFL++ stability
- Update dependencies

## 0.2.0 - 2022-09-15

- Let fuzzers continue after crash is found
- Add Arbitrary support
- Create different output directories for different fuzzing targets
- Improve TUI
- Use clap's derive syntax for the CLI code
- Various bug fixes and small improvements

## 0.1.9 - 2022-09-01

- Remove useless llvm flag for honggfuzz
- Add `--no-libfuzzer` flag to skip building/fuzzing with libfuzzer

## 0.1.8 - 2022-08-08

- Reset most of AFL's stats after each minimization for better corpus management

## 0.1.7 - 2022-08-04

- Fix corpus coverage bug

## 0.1.6 - 2022-08-04

- Add basic code coverage report generation

## 0.1.5 - 2022-08-04

- Fix timeout bug

## 0.1.4 - 2022-08-03

- Fix AFL++ timeout bug

## 0.1.3 - 2022-08-02

- Rename threads to jobs

## 0.1.2 - 2022-08-02

- Fix features usability issue

## 0.1.1 - 2022-08-02

- Introduce the first stable version of ziggy
