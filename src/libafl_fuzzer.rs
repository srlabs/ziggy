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
            corpus::{InMemoryCorpus, OnDiskCorpus},
            events::SimpleEventManager,
            executors::{inprocess::InProcessExecutor, ExitKind},
            feedbacks::{CrashFeedback, MaxMapFeedback},
            fuzzer::{Fuzzer, StdFuzzer},
            generators::RandPrintablesGenerator,
            inputs::{BytesInput, HasTargetBytes},
            monitors::SimpleMonitor,
            mutators::scheduled::{havoc_mutations, StdScheduledMutator},
            observers::{HitcountsMapObserver, StdMapObserver},
            schedulers::QueueScheduler,
            stages::mutational::StdMutationalStage,
            state::StdState,
        };
        use ziggy::libafl_bolts::{current_nanos, rands::StdRand, tuples::tuple_list, AsSlice};
        use core::time::Duration;
        use std::{env, path::PathBuf, ptr::write};
        use ziggy::libafl_targets::{EDGES_MAP, MAX_EDGES_NUM};

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
        let observer = unsafe {
            HitcountsMapObserver::new(StdMapObserver::from_mut_ptr(
                "edges",
                EDGES_MAP.as_mut_ptr(),
                MAX_EDGES_NUM,
            ))
        };

        // Feedback to rate the interestingness of an input
        let mut feedback = MaxMapFeedback::new(&observer);

        // A feedback to choose if an input is a solution or not
        let mut objective = CrashFeedback::new();

        // create a State from scratch
        let mut state = StdState::new(
            // RNG
            StdRand::with_seed(current_nanos()),
            // Corpus that will be evolved, we keep it in memory for performance
            // InMemoryCorpus::new(),
            OnDiskCorpus::new(PathBuf::from("./output/libafl/corpus")).unwrap(),
            // Corpus in which we store solutions (crashes in this example),
            // on disk so the user can get them after stopping the fuzzer
            OnDiskCorpus::new(PathBuf::from("./output/libafl/crashes")).unwrap(),
            // States of the feedbacks.
            // The feedbacks can report the data that should persist in the State.
            &mut feedback,
            // Same for objective feedbacks
            &mut objective,
        )
        .unwrap();

        // The Monitor trait define how the fuzzer stats are displayed to the user
        #[cfg(not(feature = "tui"))]
        let mon = SimpleMonitor::new(|s| println!("{s}"));
        #[cfg(feature = "tui")]
        let ui = TuiUI::with_version(String::from("Baby Fuzzer"), String::from("0.0.1"), false);
        #[cfg(feature = "tui")]
        let mon = TuiMonitor::new(ui);

        // The event manager handle the various events generated during the fuzzing loop
        // such as the notification of the addition of a new item to the corpus
        let mut mgr = SimpleEventManager::new(mon);

        // A queue policy to get testcasess from the corpus
        let scheduler = QueueScheduler::new();

        // A fuzzer with feedbacks and a corpus scheduler
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        // Create the executor for an in-process function with just one observer
        let mut executor = InProcessExecutor::new(
            &mut harness,
            tuple_list!(observer),
            &mut fuzzer,
            &mut state,
            &mut mgr,
        )
        .expect("Failed to create the Executor");

        // Generator of printable bytearrays of max size 32
        let mut generator = RandPrintablesGenerator::new(32);

        // Generate 8 initial inputs
        state
            .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8)
            .expect("Failed to generate the initial corpus");

        // Setup a mutational stage with a basic bytes mutator
        let mutator = StdScheduledMutator::new(havoc_mutations());
        let mut stages = tuple_list!(StdMutationalStage::new(mutator));

        fuzzer
            .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
            .expect("Error in the fuzzing loop");
    };
}

/*
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
                shmem::{unix_shmem, ShMemProvider},
            },
            corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
            events::{setup_restarting_mgr_std, EventConfig, EventRestarter, SimpleEventManager},
            executors::{inprocess::InProcessExecutor, InProcessForkExecutor, ExitKind, TimeoutExecutor},
            feedback_or, feedback_or_fast,
            feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
            fuzzer::{Fuzzer, StdFuzzer},
            inputs::{BytesInput, HasTargetBytes},
            monitors::{tui::{ui::TuiUI, TuiMonitor}, SimpleMonitor},
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
        use ziggy::libafl_targets::{EDGES_MAP, MAX_EDGES_NUM};

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

        //let monitor = SimpleMonitor::new(|_| {});
        //let monitor = SimpleMonitor::new(|s| println!("{s}"));

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
*/
