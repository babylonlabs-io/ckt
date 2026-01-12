#![allow(missing_docs, reason = "small integration crate for downstream use")]

use std::io::Read;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use ckt_fmtv5_types::v5::c::ReaderV5c;
use ckt_gobble::traits::GarblingInstanceConfig;
use ckt_runner_exec::{CircuitReader, GarbleTask, ReaderV5cWrapper, process_task};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::RngCore;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitFormatV5 {
    V5a,
    V5c,
}

pub fn detect_v5_format(path: impl AsRef<Path>) -> anyhow::Result<CircuitFormatV5> {
    let path = path.as_ref();
    let mut f = std::fs::File::open(path)
        .with_context(|| format!("open circuit file {}", path.display()))?;

    let mut header_prefix = [0u8; 6];
    f.read_exact(&mut header_prefix)
        .with_context(|| format!("read header prefix from {}", path.display()))?;

    if &header_prefix[0..4] != b"Zk2u" {
        bail!("unsupported file {}: bad magic", path.display());
    }
    if header_prefix[4] != 0x05 {
        bail!(
            "unsupported file {}: version {} (expected 5)",
            path.display(),
            header_prefix[4]
        );
    }

    match header_prefix[5] {
        0x00 => Ok(CircuitFormatV5::V5a),
        0x02 => Ok(CircuitFormatV5::V5c),
        other => bail!(
            "unsupported file {}: format_type 0x{other:02x} (expected 0x00 v5a or 0x02 v5c)",
            path.display()
        ),
    }
}

pub fn default_v5c_path(input: impl AsRef<Path>) -> PathBuf {
    let input = input.as_ref();
    let mut out = input.to_path_buf();
    out.set_extension("v5c.ckt");

    out
}

pub async fn ensure_v5c(input: impl AsRef<Path>) -> anyhow::Result<PathBuf> {
    let input = input.as_ref();
    match detect_v5_format(input)? {
        CircuitFormatV5::V5c => Ok(input.to_path_buf()),
        CircuitFormatV5::V5a => {
            let out = default_v5c_path(input);

            if out.exists() && matches!(detect_v5_format(&out), Ok(CircuitFormatV5::V5c)) {
                return Ok(out);
            }

            let input_str = input
                .to_str()
                .with_context(|| format!("non-utf8 input path {}", input.display()))?;
            let out_str = out
                .to_str()
                .with_context(|| format!("non-utf8 output path {}", out.display()))?;

            ckt_lvl::prealloc::prealloc(input_str, out_str)
                .await
                .with_context(|| {
                    format!("prealloc v5a→v5c: {} → {}", input.display(), out.display())
                })?;

            Ok(out)
        }
    }
}

#[derive(Debug, Clone)]
pub struct GarbledCircuitArtifacts {
    pub delta: [u8; 16],
    pub primary_input_false_labels: Vec<[u8; 16]>,
    pub garbler_output_labels: Vec<[u8; 16]>,
}

pub async fn garble_v5c_to_writer<W: Write>(
    circuit_v5c: impl AsRef<Path>,
    writer: W,
    rng: &mut ChaCha20Rng,
) -> anyhow::Result<GarbledCircuitArtifacts> {
    let circuit_v5c = circuit_v5c.as_ref();
    let mut reader = ReaderV5cWrapper::new(
        ReaderV5c::open(circuit_v5c)
            .with_context(|| format!("open v5c circuit {}", circuit_v5c.display()))?,
    );

    let header = *reader.header();

    let primary_inputs =
        usize::try_from(header.primary_inputs).context("primary_inputs does not fit usize")?;

    let scratch_space =
        u32::try_from(header.scratch_space).context("scratch_space does not fit u32")?;

    let primary_input_false_labels: Vec<_> = (0..primary_inputs)
        .map(|_| {
            let mut label = [0u8; 16];
            rng.fill_bytes(&mut label);
            label
        })
        .collect();

    let mut delta = [0u8; 16];
    rng.fill_bytes(&mut delta);

    let config = GarblingInstanceConfig {
        scratch_space,
        delta,
        primary_input_false_labels: &primary_input_false_labels,
    };

    let task = GarbleTask::new(config);
    let output = process_task(&task, writer, &mut reader)
        .await
        .context("garble: process_task")?;

    Ok(GarbledCircuitArtifacts {
        delta,
        primary_input_false_labels,
        garbler_output_labels: output.garbler_output_labels,
    })
}

pub async fn garble_v5c_to_file(
    circuit_v5c: impl AsRef<Path>,
    garbled_output_file: impl AsRef<Path>,
    rng: &mut ChaCha20Rng,
) -> anyhow::Result<GarbledCircuitArtifacts> {
    let garbled_output_file = garbled_output_file.as_ref();
    let file = std::fs::File::create(garbled_output_file)
        .with_context(|| format!("create {}", garbled_output_file.display()))?;
    let writer = std::io::BufWriter::new(file);

    garble_v5c_to_writer(circuit_v5c, writer, rng).await
}
