- Dataset: Metadata of our dataset, includes `Diff files`, `target function lists` ,`reference`, `testset` and patch evolution metadata.
- Result: experiment results for the five selected patch presence testing tools
- scripts: Python scripts of our dataset construction pipeline
- RQs: data for the five RQs of our paper
> The compiled binaries of our dataset have been uploaded to Zenodo: https://zenodo.org/records/18382612 

## Automated Dataset Construction

Our ongoing dataset-construction work now adopts a fully automated workflow
that combines LLMs with agent tools. A demo and partial experimental results
for agent-based patch presence testing are available in the
[`AGENT4PPT`](https://github.com/akaganeite/Dataset-For-Patch-Presence/tree/AGENT4PPT)
branch. The remaining implementation and supporting code will be released in
this repository in a future update.
