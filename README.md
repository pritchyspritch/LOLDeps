# LOLDeps
LOLDeps stands for Living Off the Land Dependencies, it is a simple tool that uses native package managers to highlight vulnerabilities in your package manifests and alerts you when it finds issues.

```shell
usage: LOLDeps.py [-h] [--path PATH] [--failure-level FAILURE_LEVEL] [--ado]

options:
  -h, --help            show this help message and exit
  --path PATH           Path to the directory where your code and package manifest is held.
  --failure-level FAILURE_LEVEL
                        Provide the risk level that must be failed on. Options: critical, high, moderate
  --ado                 Choose if you are running in Azure DevOps pipeline.
```