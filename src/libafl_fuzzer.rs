// To run this fuzzer, execute the following command (for example in `examples/url/`):
// LIBAFL_EDGES_MAP_SIZE=1000000 ASAN_OPTION="detect_odr_violation=0:abort_on_error=1:symbolize=0" TSAN_OPTION="report_signal_unsafe=0" RUSTFLAGS="-C passes=sancov-module -C llvm-args=-sanitizer-coverage-level=3 -C llvm-args=-sanitizer-coverage-trace-pc-guard -C llvm-args=-sanitizer-coverage-prune-blocks=0 -C llvm-args=-sanitizer-coverage-trace-compares -C opt-level=3 -C target-cpu=native --cfg fuzzing -Cdebug-assertions -Clink-arg=-fuse-ld=gold" cargo run --features=ziggy/with_libafl --target x86_64-unknown-linux-gnu

#[macro_export]
#[cfg(feature = "with_libafl")]
macro_rules! libafl_fuzz {

    ( $($x:tt)* ) => {

        use core::time::Duration;
        use std::{env, path::PathBuf, ptr::write};

        use ziggy::libafl::{
            bolts::{
                current_nanos,
                rands::StdRand,
                tuples::{tuple_list, Merge},
                AsSlice,
            },
            corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
            events::{setup_restarting_mgr_std, EventConfig, EventRestarter, SimpleEventManager},
            executors::{inprocess::InProcessExecutor, ExitKind, TimeoutExecutor},
            feedback_or, feedback_or_fast,
            feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
            fuzzer::{Fuzzer, StdFuzzer},
            inputs::{BytesInput, HasTargetBytes},
            monitors::tui::{ui::TuiUI, TuiMonitor},
            mutators::{
                scheduled::{havoc_mutations, tokens_mutations, StdScheduledMutator},
                token_mutations::Tokens,
            },
            observers::{HitcountsMapObserver, StdMapObserver, TimeObserver},
            schedulers::{
                powersched::PowerSchedule, IndexesLenTimeMinimizerScheduler, StdWeightedScheduler,
            },
            stages::{calibrate::CalibrationStage, power::StdPowerMutationalStage},
            state::{HasCorpus, HasMetadata, StdState},
            Error,
        };
        use ziggy::libafl_targets::{libfuzzer_initialize, libfuzzer_test_one_input, EDGES_MAP, MAX_EDGES_NUM};

        // The closure that we want to fuzz
        let inner_harness = $($x)*;

        // The wrapped harness function, calling out to the LLVM-style harness
        let mut harness = |input: &BytesInput| {
            let target = input.target_bytes();
            let buf = target.as_slice();
            inner_harness(buf);
            ExitKind::Ok
        };

        let ui = TuiUI::with_version(String::from("Baby Fuzzer"), String::from("0.0.1"), false);
        let monitor = TuiMonitor::new(ui);

        let objective_dir = PathBuf::from("./crashes");
        let corpus_dirs = &[PathBuf::from("./corpus")];

        // Create an observation channel using the coverage map
        let edges_observer = unsafe {
            HitcountsMapObserver::new(StdMapObserver::from_mut_ptr(
                "edges",
                EDGES_MAP.as_mut_ptr(),
                MAX_EDGES_NUM,
            ))
        };

        // Create an observation channel to keep track of the execution time
        let time_observer = TimeObserver::new("time");

        let map_feedback = MaxMapFeedback::tracking(&edges_observer, true, true);

        let calibration = CalibrationStage::new(&map_feedback);

        // Feedback to rate the interestingness of an input
        // This one is composed by two Feedbacks in OR
        let mut feedback = feedback_or!(
            // New maximization map feedback linked to the edges observer and the feedback state
            map_feedback,
            // Time feedback, this one does not need a feedback state
            TimeFeedback::with_observer(&time_observer)
        );

        // A feedback to choose if an input is a solution or not
        let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

        // If not restarting, create a State from scratch
        let mut state = StdState::new(
                // RNG
                StdRand::with_seed(current_nanos()),
                // Corpus that will be evolved, we keep it in memory for performance
                InMemoryCorpus::new(),
                // Corpus in which we store solutions (crashes in this example),
                // on disk so the user can get them after stopping the fuzzer
                OnDiskCorpus::new(objective_dir).unwrap(),
                // States of the feedbacks.
                // The feedbacks can report the data that should persist in the State.
                &mut feedback,
                // Same for objective feedbacks
                &mut objective,
            )
            .unwrap();

        println!("We're a client, let's fuzz :)");

        // Setup a basic mutator with a mutational stage
        let mutator = StdScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));

        let power = StdPowerMutationalStage::new(mutator);

        let mut stages = tuple_list!(calibration, power);

        // A minimization+queue policy to get testcasess from the corpus
        let scheduler = IndexesLenTimeMinimizerScheduler::new(StdWeightedScheduler::with_schedule(
            &mut state,
            &edges_observer,
            Some(PowerSchedule::FAST),
        ));

        // A fuzzer with feedbacks and a corpus scheduler
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        let mut mgr = SimpleEventManager::new(monitor);

        // Create the executor for an in-process function with one observer for edge coverage and one for the execution time
        let mut executor = TimeoutExecutor::new(
            InProcessExecutor::new(
                &mut harness,
                tuple_list!(edges_observer, time_observer),
                &mut fuzzer,
                &mut state,
                &mut mgr,
            ).unwrap(),
            // 10 seconds timeout
            Duration::new(10, 0),
        );

        // In case the corpus is empty (on first run), reset
        if state.must_load_initial_inputs() {
            state
                .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, corpus_dirs)
                .unwrap_or_else(|_| panic!("Failed to load initial corpus at {:?}", &corpus_dirs));
            println!("We imported {} inputs from disk.", state.corpus().count());
        }

        fuzzer.fuzz_loop(
            &mut stages,
            &mut executor,
            &mut state,
            &mut mgr,
        ).unwrap();
    };
}
