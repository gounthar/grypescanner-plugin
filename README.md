# Grype vulnerability scanner

## Introduction

[Grype](https://github.com/anchore/grype) is a vulnerability scanner for container images and filesystems.
This jenkins plugin scans a given target and saves a report as job artifact.


## Getting started
This jenkins plugin installs grype in the job workspace directory and performs scan.
See section [Installation/Recommended](https://github.com/anchore/grype) for more installation details.


#### Grype as a build step:
<img src="images/1.png" alt="Grype plugin" />

<img src="images/2.png" alt="Grype plugin" />

#### Possible scan targets:
<img src="images/3.png" alt="Grype plugin" />

#### Scan result as job artifact:
<img src="images/4.png" alt="Grype plugin" />

#### Scan results:
<img src="images/5.png" alt="Grype plugin" />


### Usage in a pipeline:
```groovy
pipeline
{
  agent any
  options
  {
    skipStagesAfterUnstable()
  }
  stages
  {
    stage('Build')
    {
      steps
      {
        grypeScan scanDest: 'dir:/tmp', repName: 'myScanResult.txt'
      }
    }
  }
}
```

## Issues

TODO Decide where you're going to host your issues, the default is Jenkins JIRA, but you can also enable GitHub issues,
If you use GitHub issues there's no need for this section; else add the following line:

Report issues and enhancements in the [Jenkins issue tracker](https://issues.jenkins-ci.org/).

## Contributing

TODO review the default [CONTRIBUTING](https://github.com/jenkinsci/.github/blob/master/CONTRIBUTING.md) file and make sure it is appropriate for your plugin, if not then add your own one adapted from the base file

Refer to our [contribution guidelines](https://github.com/jenkinsci/.github/blob/master/CONTRIBUTING.md)

## LICENSE

Licensed under MIT, see [LICENSE](LICENSE.md)

