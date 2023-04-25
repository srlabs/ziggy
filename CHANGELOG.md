# Changes

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