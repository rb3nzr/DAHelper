## About
DAHelper is a script that I put together as something to run with procmon, regshot etc., for initial analysis. It will set a series of baselines, monitor new process and file creation, run a second series of baselines, then diff the two sets and print/log results.

**Requires [pe-sieve](https://github.com/hasherezade/pe-sieve/releases), [MFTECmd](https://ericzimmerman.github.io/#!index.md), and [ExtractUsnJrnl](https://github.com/jschicht/ExtractUsnJrnl?tab=readme-ov-file) in script root.**

Between baseline sets: 
  - pe-sieve will run on newly spawned processes (output will be 'sieve-output' in script root) and their modules will be listed.
  - When a file creation event is triggered, the file will be copied to 'copied_files' in script root.

