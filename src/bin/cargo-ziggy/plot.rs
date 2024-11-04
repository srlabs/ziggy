use crate::PathBuf;
use crate::{find_target, Plot};
use anyhow::{Context, Result};
use chrono::{DateTime, Local};
use plotly::layout::Layout;
use plotly::{Plot as Plotly, Scatter};
use std::fs;
use std::{env, process};

impl Plot {
    pub fn generate_plot(&mut self) -> Result<(), anyhow::Error> {
        eprintln!("Generating plot");

        self.target =
            find_target(&self.target).context("⚠️  couldn't find the target for plotting")?;

        // The cargo executable
        let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));

        let fuzzer_data_dir = format!(
            "{}/{}/afl/{}/",
            &self.ziggy_output.display(),
            &self.target,
            &self.input
        );

        let plot_dir = self
            .output
            .display()
            .to_string()
            .replace("{ziggy_output}", &self.ziggy_output.display().to_string())
            .replace("{target_name}", &self.target);

        println!("{plot_dir}");
        println!("{}", self.target);

        // We run the afl-plot command
        process::Command::new(cargo)
            .args(["afl", "plot", &fuzzer_data_dir, &plot_dir])
            .spawn()
            .context("⚠️  couldn't spawn afl plot")?
            .wait()
            .context("⚠️  couldn't wait for the afl plot")?;

        let dir_path = PathBuf::from(
            &self
                .corpus
                .display()
                .to_string()
                .replace("{ziggy_output}", &self.ziggy_output.display().to_string())
                .replace("{target_name}", &self.target),
        );

        match Self::plot_corpus(
            &dir_path,
            &PathBuf::from(format!(
                "{}/{}/",
                &self.ziggy_output.display(),
                &self.target
            )),
        ) {
            Ok(_) => {}
            Err(e) => println!(
                "Couldn't plot the corpus count : {:?} with {:?}",
                e, dir_path
            ),
        }

        Ok(())
    }

    /// This function plot using Plotly the corpus count into a HTML file.
    /// This allows the developper to have a better visualization of the corpus evolution
    pub fn plot_corpus(
        corpus_path: &PathBuf,
        output: &PathBuf,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut data: Vec<(DateTime<Local>, usize)> = Vec::new();
        let mut edge_count = 0;

        for entry in fs::read_dir(corpus_path)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                edge_count += 1;
                if let Ok(metadata) = fs::metadata(&path) {
                    if let Ok(created) = metadata.created() {
                        let datetime: DateTime<Local> = created.into();
                        data.push((datetime, edge_count));
                    }
                }
            }
        }

        data.sort_by_key(|k| k.0);

        let x: Vec<String> = data
            .iter()
            .map(|(dt, _)| dt.format("%Y-%m-%d %H:%M:%S").to_string())
            .collect();
        let y: Vec<usize> = data.iter().map(|(_, count)| *count).collect();

        let trace = Scatter::new(x, y)
            .name("Edge Count")
            .mode(plotly::common::Mode::LinesMarkers);

        let mut plot = Plotly::new();
        plot.add_trace(trace);

        let layout = Layout::new()
            .title("Corpus Count Evolution")
            .x_axis(plotly::layout::Axis::new().title("Date"))
            .y_axis(plotly::layout::Axis::new().title("Corpus Count"));
        plot.set_layout(layout);

        let output_path = PathBuf::from(output).join("plot_corpus");

        if !output_path.exists() {
            fs::create_dir_all(&output_path).expect("Failed to create plot_corpus directory");
        }

        let final_dest = output_path.join("index.html");
        plot.write_html(final_dest.clone());

        println!(
            "Corpus Count tracker has been saved as in {}",
            output_path.display()
        );

        Ok(())
    }
}
