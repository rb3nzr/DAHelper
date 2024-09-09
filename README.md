DAHelper is a script that I put together to run with procmon, regshot etc., for initial dynamic analysis.

### Actions
+ Sets a series of baselines.
+ Starts up a WMI event to monitor new process creations. For each new process the loaded modules are listed as being valid/invalid via signature validation. PE-Sieve is run over each process and any results are saved in the results directory.
+ Starts up file system watchers for specific directories, and on file creation events those files are copied to the results directory.
+ A second series of baselines are run.
+ Baseline files are then diffed and the results are printed/logged.

Requires [pe-sieve](https://github.com/hasherezade/pe-sieve/releases), [MFTECmd](https://ericzimmerman.github.io/#!index.md), and [ExtractUsnJrnl](https://github.com/jschicht/ExtractUsnJrnl?tab=readme-ov-file) in script root. The option to download these on a first run will be given, as well as the option to install Sysmon with a trace config. If running initially without an internet connection then download these tools and match or change the paths in the script. These are not mandatory and if the script does not find them the those functions will be skipped.

### Options 
```
[Run-All]
\__ Runs everything in the script
\__ Baselines > Watchers/Process Monitoring > Baselines > Compare

[Watch]
\__ Starts up the only the process monitoring and file creation functions

[Single] <OutputPath>
\__ Runs a single baseline set

[Compare] <Dir 1> <Dir 2>
\__ Compares two previously exported baseline sets

[Help] To print this menu again

Example: .\DAHelper.ps1 Compare .\baselines_<time> .\baslines_<time>
```

