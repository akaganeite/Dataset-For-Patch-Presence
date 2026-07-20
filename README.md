- Dataset: Metadata of our dataset, includes `Diff files`, `target function lists` ,`reference`, `testset` and patch evolution metadata.
- Result: experiment results for the five selected patch presence testing tools
- scripts: Python scripts of our dataset construction pipeline
- RQs: data for the five RQs of our paper
> The compiled binaries of our dataset have been uploaded to Zenodo: https://zenodo.org/records/18382612 

## Automated Dataset Construction

1. **Agent-PPT demo.** A demo and partial experimental results for the
   agent-based patch presence testing idea discussed in the paper's Discussion
   section are available in the
   [`AGENT4PPT`](https://github.com/akaganeite/Dataset-For-Patch-Presence/tree/AGENT4PPT)
   branch.
2. **Automated dataset construction and extension.** For the core dataset
   studied in this paper, we are developing an automated workflow that combines
   LLMs with agent tools to construct and extend the dataset. The corresponding
   code will be released in this repository soon.
