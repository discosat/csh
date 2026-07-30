#!/usr/bin/env python3
"""

This handy script creates a `doppler.txt` from a gqrx recording 
**without a TLE** for the doppler correction bloc in GNURadio.


It was originally made because the TLE of DISCO-2 had changed
overtime and old recordings' analysis using new TLEs didn't result
in anything

As the TLE has become much better, this will probably just be history
for early DISCO-2 decoding days. Specially as we move towards automating everything

Usage
-----
    python generate_doppler.py <file.raw>
    python generate_doppler.py <file.raw> --carrier-hz 437075000
    python generate_doppler.py --help

Produces <gqrx_stem>_doppler.txt next to the .raw file and prints the first
unix timestamp (t0) of that file to stdout for your convenience
"""

import argparse
import os
import sys
from datetime import datetime, timezone
from math import pi
from mmap import mmap, ACCESS_READ

import numpy as np
from numpy.typing import NDArray
from scipy.signal import (
    decimate as _decimate,
    spectrogram as _spectrogram,
    find_peaks,
    medfilt,
)
from tqdm import tqdm

# General settings

DEFAULT_CARRIER_HZ = 437_075_000.0  # DISCO-2 transmit frequency
ANALYSIS_DECIM = 10  # 500 kHz -> 50 kHz for the spectrogram (new standard for 500KHz recording)
CHUNK_SECONDS = 30.0  # to not destroy your RAM, can be increased if you have a lot of RAM
SPEC_NPERSEG = 2048  
SPEC_AVG = 25  # average this many spectrogram time-slices
PEAK_THRESHOLD_DB = 8.0  # dB above local cleaned noise floor
PEAK_DISTANCE = 25  # min freq-bins between peaks
FREQ_SEARCH_HALFWIDTH = 12_000  # +/- Hz around baseband to search for the signal
DOPPLER_CADENCE_S = 1.0  # output for GNU radio doppler block (seconds)


def parse_gqrx_filename(path: str) -> tuple[float, float, float]:
    """Parse gqrx_YYYYMMDD_HHMMSS_<centerHz>_<sampRate>_fc(.raw|.wav).

    Returns (recording_start_unix, center_hz, samp_rate).
    """
    basename = os.path.basename(path)
    stem = basename[:-4] if basename.endswith((".raw", ".wav")) else basename
    parts = stem.split("_")
    if len(parts) < 6 or parts[0] != "gqrx" or parts[-1] != "fc":
        raise ValueError(
            f"Filename does not match gqrx format "
            f"(gqrx_YYYYMMDD_HHMMSS_centerHz_sampleRate_fc.raw): {basename}"
        )
    dt = datetime.strptime(f"{parts[1]}_{parts[2]}", "%Y%m%d_%H%M%S").replace(
        tzinfo=timezone.utc
    )
    return dt.timestamp(), float(parts[3]), float(parts[4])


def decimate_complex(x: NDArray[np.complex64], q: int) -> NDArray[np.complex64]:
    """Decimate a complex array by integer q (real/imag separately)."""
    I = _decimate(x.real, q=q, zero_phase=True)
    Q = _decimate(x.imag, q=q, zero_phase=True)
    return I + 1j * Q


def analyze_recording(
    raw_path: str,
    samp_rate: float,
    center_offset_hz: float,
ear   chunk_seconds: float = CHUNK_SECONDS,
    analysis_decim: int = ANALYSIS_DECIM,
    spec_nperseg: int = SPEC_NPERSEG,
    spec_avg: int = SPEC_AVG,
    peak_threshold_db: float = PEAK_THRESHOLD_DB,
    peak_distance: int = PEAK_DISTANCE,
    freq_search_halfwidth: float = FREQ_SEARCH_HALFWIDTH,
) -> tuple[NDArray[np.float64], NDArray[np.float64]]:

    """Stream the raw file in chunks and return detected Doppler peaks
    (det_t, det_f).

        Ignore the horrendous number of parameters for this function,
        a data class can easily solve it and it's in my #TODOs
    """
    spec_rate = samp_rate / analysis_decim  # 50 kHz
    chunk_samples = int(chunk_seconds * samp_rate)
    chunk_bytes = chunk_samples * np.dtype(np.complex64).itemsize
    file_size = os.path.getsize(raw_path)

    dphi = 2.0 * pi * center_offset_hz / samp_rate
    phase_acc = 0.0

    Sxx_parts, t_parts = [], []
    f_arr = None
    noverlap = int(spec_nperseg * 0.75)

    with open(raw_path, "rb") as fh:
        mm = mmap(fh.fileno(), 0, access=ACCESS_READ)
        pbar = tqdm(total=file_size, unit="B", unit_scale=True, desc="Analysing")
        offset = 0
        while offset < file_size:
            this_bytes = min(chunk_bytes, file_size - offset)
            n_samp = this_bytes // np.dtype(np.complex64).itemsize
            if n_samp < spec_nperseg:
                break
            iq = np.frombuffer(
                mm, dtype=np.complex64, count=n_samp, offset=offset
            )

            n = np.arange(n_samp)
            phase = phase_acc + dphi * n
            rot = np.exp(-1j * phase).astype(np.complex64)
            iq_bb = (iq * rot).astype(np.complex64)
            del iq, rot, phase
            phase_acc = (phase_acc + dphi * n_samp) % (2.0 * pi)

            chunk_t0 = offset // np.dtype(np.complex64).itemsize / samp_rate

            iq_spec = decimate_complex(iq_bb, analysis_decim)
            f_c, t_c, Sxx_c = _spectrogram(
                iq_spec,
                fs=spec_rate,
                nperseg=spec_nperseg,
                noverlap=noverlap,
                window="hamming",
                return_onesided=False,
            )
            del iq_spec
            f_arr = f_c
            n_avg = (Sxx_c.shape[1] // spec_avg) * spec_avg
            if n_avg > 0:
                Sxx_a = (
                    Sxx_c[:, :n_avg].reshape(Sxx_c.shape[0], -1, spec_avg).mean(axis=2)
                )
                t_a = t_c[:n_avg:spec_avg] + chunk_t0
                Sxx_parts.append(Sxx_a)
                t_parts.append(t_a)

            del iq_bb
            offset += this_bytes
            pbar.update(this_bytes)
        pbar.close()
        mm.close()

    if not Sxx_parts:
        sys.exit("ERROR: no spectrogram data produced (file too short?)")

    Sxx = np.concatenate(Sxx_parts, axis=1)
    t_avg = np.concatenate(t_parts)
    del Sxx_parts, t_parts

    # ── clean spectrogram (remove freq- and time-persistent energy) ──
    f_shifted = np.fft.fftshift(f_arr)
    Sxx_shifted = np.fft.fftshift(Sxx, axes=0)
    del Sxx
    Sxx_db = 10.0 * np.log10(Sxx_shifted + 1e-12)
    del Sxx_shifted
    Sxx_clean = Sxx_db - np.mean(Sxx_db, axis=1, keepdims=True)
    Sxx_clean = Sxx_clean - np.median(Sxx_clean, axis=0, keepdims=True)
    del Sxx_db

    noise_floor = float(np.median(Sxx_clean))
    freq_mask = np.abs(f_shifted) <= freq_search_halfwidth

    det_t, det_f = [], []
    for i in range(Sxx_clean.shape[1]):
        col = Sxx_clean[:, i].copy()
        col[~freq_mask] = noise_floor
        peaks, props = find_peaks(
            col, height=noise_floor + peak_threshold_db, distance=peak_distance
        )
        if len(peaks) > 0:
            strongest = peaks[int(np.argmax(props["peak_heights"]))]
            det_t.append(t_avg[i])
            det_f.append(f_shifted[strongest])

    det_t = np.array(det_t, dtype=np.float64)
    det_f = np.array(det_f, dtype=np.float64)

    return det_t, det_f

# Doppler curve post-processing

def smooth_doppler(
    det_t: NDArray[np.float64],
    det_f: NDArray[np.float64]) -> tuple[NDArray[np.float64], NDArray[np.float64]]:
    if len(det_f) < 4:
        return det_t, det_f
    k = min(15, len(det_f) // 3)
    if k % 2 == 0:
        k += 1
    if k >= 3:
        det_f = medfilt(det_f, kernel_size=k)
    # remove points whose step from the previous kept sample exceeds 500 Hz/s
    if len(det_t) > 2:
        max_step = 500.0
        keep = [0]
        for i in range(1, len(det_t)):
            dt = det_t[i] - det_t[keep[-1]]
            if dt <= 0:
                continue
            rate = abs(det_f[i] - det_f[keep[-1]]) / dt
            if rate <= max_step:
                keep.append(i)
        det_t = det_t[keep]
        det_f = det_f[keep]
    return det_t, det_f


def write_doppler_txt(
    out_path: str,
    det_t: NDArray[np.float64],
    det_f: NDArray[np.float64],
    rec_start_unix: float,
    duration_s: float,
    cadence: float = DOPPLER_CADENCE_S) -> tuple[NDArray[np.float64], NDArray[np.float64]]:

    if len(det_t) == 0:
        # No signal detected - emit a flat zero-Doppler table so the block
        # still has a valid file to read.
        grid_t = np.arange(0.0, duration_s + cadence, cadence)
        grid_f = np.zeros_like(grid_t)
    else:
        det_t, det_f = smooth_doppler(det_t, det_f)
        grid_t = np.arange(0.0, duration_s + cadence, cadence)
        grid_f = np.interp(grid_t, det_t, det_f)

    with open(out_path, "w") as fh:
        for t, f in zip(grid_t, grid_f):
            fh.write(f"{rec_start_unix + t:.6f} {f:.6f}\n")

    return grid_t, grid_f


def main() -> None:
    ap = argparse.ArgumentParser(
        description=(
            "Analyse a gqrx .raw DISCO-2 recording and produce "
            "<stem>_doppler.txt for the GNURadio decoder. Prints "
            "the first unix timestamp (t0) of the doppler file."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument(
        "input",
        help="Path to the gqrx .raw IQ file (gqrx filename is "
        "auto-parsed for centre freq, sample rate and "
        "recording start).",
    )
    ap.add_argument(
        "--carrier-hz",
        type=float,
        default=DEFAULT_CARRIER_HZ,
        help=f"Satellite transmit frequency (default " f"{DEFAULT_CARRIER_HZ:.0f})",
    )
    ap.add_argument(
        "--chunk-seconds",
        type=float,
        default=CHUNK_SECONDS,
        help=f"IQ seconds per batch (default {CHUNK_SECONDS})",
    )
    ap.add_argument(
        "--peak-threshold-db",
        type=float,
        default=PEAK_THRESHOLD_DB,
        help=f"DB above noise for Doppler peak detection "
        f"(default {PEAK_THRESHOLD_DB})",
    )
    args = ap.parse_args()

    raw_path = args.input
    if not os.path.exists(raw_path):
        sys.exit(f"ERROR: input file not found: {raw_path}")

    # ── recording metadata ──
    try:
        rec_start, center_hz, samp_rate = parse_gqrx_filename(raw_path)
    except ValueError as exc:
        sys.exit(f"ERROR: {exc}")

    carrier_hz = args.carrier_hz
    center_offset_hz = carrier_hz - center_hz

    file_size = os.path.getsize(raw_path)
    total_samples = file_size // np.dtype(np.complex64).itemsize
    duration_s = total_samples / samp_rate

    # output path ──
    raw_dir = os.path.dirname(os.path.abspath(raw_path))
    stem = os.path.splitext(os.path.basename(raw_path))[0]
    doppler_path = os.path.join(raw_dir, f"{stem}_doppler.txt")

    try:
        det_t, det_f = analyze_recording(
            raw_path,
            samp_rate,
            center_offset_hz,
            chunk_seconds=args.chunk_seconds,
            peak_threshold_db=args.peak_threshold_db,
        )
    except Exception as exc:
        sys.exit(f"ERROR analysing recording: {exc}")
    write_doppler_txt(doppler_path, det_t, det_f, rec_start, duration_s)

    print(f"{rec_start:.6f}")


if __name__ == "__main__":
    main()
