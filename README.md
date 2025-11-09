🧩 DESCRIPTION – Genetic Algorithm for ECDSA Nonce Search (English)

This script implements a research/experimental tool that tries to find a candidate ECDSA nonce `k`
which makes many observed signatures consistent with a single private key `d`.  
It uses a **genetic algorithm (DEAP)** to search the integer space of possible `k` values and
evaluates candidates using a cryptographic objective function derived from ECDSA math.

──────────────────────────────────────────────────────────────
🎯 PURPOSE

Given a set of ECDSA signatures (each with `r`, `s`, `z`), the script:
- attempts to recover a private key `d` for a candidate `k` using the relation:
    d = ((s * k - z) * r^{-1}) mod n
- scores each candidate `k` by how consistent the recovered `d` values are across signatures
  (smaller inconsistency → better candidate)
- uses a GA to evolve `k` values that minimize that inconsistency

This is a **proof-of-concept** for exploring weaknesses from bad nonce generation (reused/biased k).
Use only on test data or keys you own.

──────────────────────────────────────────────────────────────
📦 MAIN PARTS (high level)

1.  Signature data
    - `signatures` list: each entry is a dict with integer `r`, `s`, `z` (hex→int).
    - Replace or extend this list with the signatures you want to analyze.

2.  Core ECDSA math
    - `n`: curve order for secp256k1 (constant).
    - `recover_d(r, s, z, k)`: compute candidate private key `d` for a single signature and `k`.
      Uses modular inverse of `r` (`inverse_mod`).

3.  Objective / fitness
    - `objective(k, signatures)`: for a k candidate compute d for every signature.
      If `d` cannot be computed for a signature, a large penalty value `n` is used.
      The objective/error is the sum of absolute pairwise differences between all recovered d's.
      Lower error means recovered ds are more consistent (ideal zero means all equal).

4.  Genetic Algorithm (DEAP)
    - Individuals: a single integer `k` in [1, n-1]
    - Fitness: minimize the objective error
    - Operators:
      - Crossover: uniform (`cxUniform`)
      - Mutation: Gaussian mutation (`mutGaussian`, sigma = n//1000)
      - Selection: tournament (`selTournament`, tournsize=3)
    - Evolution loop runs for `NGEN` generations with a population size (`n=50` in main()).

──────────────────────────────────────────────────────────────
🛠 HOW IT WORKS (main loop)

- Initialize a randomized GA population of k candidates.
- For each generation:
  - Create offspring via crossover + mutation.
  - Evaluate fitness (objective) of each offspring.
  - Select the next population using tournament selection.
  - Track and print the current best k and its error.
- Optionally break early if the best error is below a threshold (e.g., <100).
- Output the best candidate k and the corresponding estimated private key(s) d.

──────────────────────────────────────────────────────────────
KEY FUNCTIONS

- `recover_d(r, s, z, k)` — compute d from a single signature and k (cached by `lru_cache`).
- `objective(k, signatures)` — compute error and list of candidate d values for scoring.
- GA setup (`creator`, `toolbox`) — DEAP configuration and registered operators.
- `eval_individual(individual)` — wrapper to evaluate one individual for DEAP.

──────────────────────────────────────────────────────────────
USAGE

1. Populate the `signatures` list with the signatures you want to analyze (each r,s,z as int).
2. Run:

    python your_script_name.py

3. Observe printed generation-by-generation progress and final best candidate.

──────────────────────────────────────────────────────────────
DEPENDENCIES

Install with pip:

    pip install ecdsa deap

(plus Python standard libraries: math, random, functools)

──────────────────────────────────────────────────────────────
LIMITATIONS & NOTES

- The script assumes signatures are produced by the same private key and that a single k
  (or k with strong correlation) can make recovered d values consistent.
- The objective function is simple (pairwise absolute differences); consider more robust
  scoring if needed (e.g., normalized variance, address verification).
- GA hyperparameters (population size, generations, mutation sigma) may need tuning.
- This is a stochastic search — results are not guaranteed and can be computationally expensive.

──────────────────────────────────────────────────────────────
⚠️ LEGAL & ETHICAL DISCLAIMER

This code is for **educational and research purposes only**.  
Do not attempt to use it to recover private keys or access cryptocurrency wallets that you
do not own or are not explicitly authorized to test. Unauthorized use may be illegal.

──────────────────────────────────────────────────────────────
SUMMARY

A DEAP-based genetic search for candidate ECDSA nonces `k` that yields consistent candidate
private keys across multiple signatures. Useful as a research prototype for exploring nonce-related vulnerabilities.


BTC donation address: bc1q4nyq7kr4nwq6zw35pg0zl0k9jmdmtmadlfvqhr
