## Contributing

Thank your for contributing to this project! We welcome collaborators and expect users to follow our [code of conduct](CODE_OF_CONDUCT.md) when submitting code or comments.

1. Fork the repo ( https://github.com/poanetwork/hbbft/fork ).
2. Create your feature branch (`git checkout -b my-new-feature`).
3. Write tests that cover your work.
4. Run Rustfmt, Clippy, and all tests to ensure CI rules are satisfied. Correct versions and feature flags can be found in the [`.travis.yml`](https://github.com/poanetwork/hbbft/blob/master/.travis.yml) file.
5. Commit your changes (`git commit -am 'Add some feature'`).
6. Push to your branch (`git push origin my-new-feature`).
7. Create a new Pull Request.

### General

* Commits should be one logical change that still allows all tests to pass.  We prefer smaller commits if there could be two levels of logic grouping.  The goal is to provide future contributors (including your future self) the reasoning behind your changes and allow them to cherry-pick, patch or port those changes in isolation to other branches or forks.
* If during your PR you reveal a pre-existing bug:
  1. Try to isolate the bug and fix it on an independent branch and PR it first.
  2. Try to fix the bug in a separate commit from other changes:
     1. Commit the code in the broken state that revealed the bug originally
     2. Commit the fix for the bug.
     3. Continue original PR work.

### Pull Requests
All pull requests should include: 
* A clear, readable description of the purpose of the PR
* A clear, readable description of changes
* Any additional concerns or comments (optional)