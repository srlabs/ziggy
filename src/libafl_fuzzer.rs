// To run this fuzzer, execute the following command (for example in `examples/url/`):
// For some reason, using +nightly speeds up the performance quite a lot.
// LIBAFL_EDGES_MAP_SIZE=500000 RUSTFLAGS="-C passes=sancov-module -C llvm-args=-sanitizer-coverage-level=3 -C llvm-args=-sanitizer-coverage-trace-pc-guard --cfg fuzzing -Clink-arg=-fuse-ld=gold" cargo run --features=ziggy/with_libafl --target x86_64-unknown-linux-gnu --release

//! In-Memory fuzzing made easy.
//! Use this sugar for scaling `libfuzzer`-style fuzzers.

#[macro_export]
#[cfg(feature = "with_libafl")]
macro_rules! libafl_fuzz {

    ( $($x:tt)* ) => {
        use ziggy::libafl::{
            corpus::{InMemoryCorpus, OnDiskCorpus, Corpus},
            events::{setup_restarting_mgr_std, EventConfig, EventRestarter, SimpleEventManager},
            executors::{inprocess::InProcessExecutor, InProcessForkExecutor, ExitKind, TimeoutExecutor},
            feedback_or, feedback_or_fast,
            feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
            fuzzer::{Fuzzer, StdFuzzer},
            generators::RandPrintablesGenerator,
            inputs::{BytesInput, HasTargetBytes},
            monitors::SimpleMonitor,
            mutators::{
                scheduled::{havoc_mutations, tokens_mutations, StdScheduledMutator},
                token_mutations::Tokens,
            },
            observers::{HitcountsMapObserver, StdMapObserver, TimeObserver},
            schedulers::{
                powersched::PowerSchedule, IndexesLenTimeMinimizerScheduler, StdWeightedScheduler,
            },
            stages::{calibrate::CalibrationStage, power::StdPowerMutationalStage, sync::SyncFromDiskStage},
            state::{HasCorpus, StdState},
        };
        use ziggy::libafl_bolts::{current_nanos, rands::StdRand, tuples::{Merge, tuple_list}, AsSlice};
        use core::time::Duration;
        use std::{env, path::PathBuf, ptr::write};
        use ziggy::libafl_targets::{EDGES_MAP, MAX_EDGES_NUM};

        // Environement variables are passed from ziggy to LibAFL
        let target_name = env::var("LIBAFL_TARGET_NAME").expect("Could not find LIBAFL_TARGET_NAME env variable");
        let client_identifier = env::var("LIBAFL_IDENTIFIER").expect("Could not find LIBAFL_IDENTIFIER env variable").parse::<u8>().unwrap_or(0);
        let shared_corpus: PathBuf = env::var("LIBAFL_SHARED_CORPUS").expect("Could not find LIBAFL_SHARED_CORPUS env variable").into();
        let libafl_corpus: PathBuf = env::var("LIBAFL_CORPUS").expect("Could not find LIBAFL_CORPUS env variable").into();
        let crashes_dir: PathBuf = env::var("LIBAFL_CRASHES").expect("Could not find LIBAFL_CRASHES env variable").into();

        // The wrapped harness function, calling out to the LLVM-style harness
        let mut harness = |input: &BytesInput| {
            let target = input.target_bytes();
            let buf = target.as_slice();
            // The closure that we want to fuzz
            let inner_harness = $($x)*;
            inner_harness(buf);
            ExitKind::Ok
        };

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

        // Feedback to rate the interestingness of an input
        let mut map_feedback = MaxMapFeedback::tracking(&edges_observer, true, true);

        let calibration = CalibrationStage::new(&map_feedback);

        let sync = SyncFromDiskStage::with_from_file(shared_corpus.clone());

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

        // create a State from scratch
        let mut state = StdState::new(
            // RNG
            StdRand::with_seed(current_nanos()),
            // Corpus that will be evolved
            OnDiskCorpus::new(&libafl_corpus).unwrap(),
            // Corpus in which we store solutions (crashes in this example),
            // on disk so the user can get them after stopping the fuzzer
            OnDiskCorpus::new(&crashes_dir).unwrap(),
            // States of the feedbacks.
            // The feedbacks can report the data that should persist in the State.
            &mut feedback,
            // Same for objective feedbacks
            &mut objective,
        )
        .unwrap();

        // The Monitor trait define how the fuzzer stats are displayed to the user
        let mon = SimpleMonitor::new(|s| println!("{s}"));

        // The event manager handle the various events generated during the fuzzing loop
        // such as the notification of the addition of a new item to the corpus
        let mut mgr = SimpleEventManager::new(mon);

        // We derive the strategy from the client identifier (given by ziggy)
        let strategy = match client_identifier % 6 {
            0 => PowerSchedule::EXPLORE,
            1 => PowerSchedule::EXPLOIT,
            2 => PowerSchedule::FAST,
            3 => PowerSchedule::COE,
            4 => PowerSchedule::LIN,
            _ => PowerSchedule::QUAD,
        };

        // A minimization+queue policy to get testcasess from the corpus
        let scheduler = IndexesLenTimeMinimizerScheduler::new(StdWeightedScheduler::with_schedule(
            &mut state,
            &edges_observer,
            Some(strategy),
        ));

        // A fuzzer with feedbacks and a corpus scheduler
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        // Create the executor for an in-process function with just one observer
        let mut executor = InProcessExecutor::new(
            &mut harness,
            tuple_list!(edges_observer, time_observer),
            &mut fuzzer,
            &mut state,
            &mut mgr,
        )
        .expect("Failed to create the Executor");

        let corpus_dirs = &[libafl_corpus, shared_corpus];

        // In case the corpus is empty (on first run), reset
        if state.must_load_initial_inputs() {
            state
                .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, corpus_dirs)
                .unwrap_or_else(|_| panic!("Failed to load initial corpus at {:?}", &corpus_dirs));
            println!("We imported {} inputs from disk.", state.corpus().count());
        }

        // Setup a basic mutator with a mutational stage
        let mutator = StdScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));

        let power = StdPowerMutationalStage::new(mutator);

        let mut stages = tuple_list!(calibration, power, sync);

        fuzzer
            .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
            .expect("Error in the fuzzing loop");
    };
}
