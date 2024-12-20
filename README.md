# LOLDeps
LOLDeps stands for Living Off the Land Dependencies, it is a simple lightweight python tool that uses native package managers to highlight vulnerabilities in your package manifests and alerts you when it finds issues.

This tool was built to allow outdated packages to be discovered using the package manager vulnerability reporting modern languages often ship with. The need came from a project where .NET and nuget were in use and there was a need/want to raise errors in pipelines for vulnerability issues in packages without the need to install and maintain complex tooling when the package manager itself already does the job perfectly well. This tool simply makes it easier to run those checks, display issues, and break builds when issues are found.


## Install

`pip install LOLDeps`


## Usage

```shell
usage: lold [-h] [--path PATH] [--failure-level FAILURE_LEVEL] [--ado]

options:
  -h, --help            show this help message and exit
  --path PATH           Path to the directory where your code and package manifest is held.
  --failure-level FAILURE_LEVEL
                        Provide the risk level that must be failed on. Options: critical, high, moderate
  --ado                 Choose if you are running in Azure DevOps pipeline.
```

## Currently supported 

- dotnet list package --vulnerable (.net)
- Azure DevOps pipelines error messaging

## Roadmap

- npm audit (js)
- gem audit (ruby)
- GitHub Actions pipeline error messaging
- slack webhook integration options