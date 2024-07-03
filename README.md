## About
**Requires [pe-sieve](https://github.com/hasherezade/pe-sieve/releases) in script root.**

Script that I put together as something to run with procmon, regshot etc., for initial analysis. It will set a series of baselines, watch processes and dropped files, run a second series of baselines, then diff the two sets and print/log results.
Between baseline sets: 
  - pe-sieve will run on all newly spawned processes (I need to make a process exclusion list).
  - Modules will be listed.
  - Files will get copied to a directory in script root on creation events.

Run the script > wait > run the sample > hit enter > wait > get stuff :)
