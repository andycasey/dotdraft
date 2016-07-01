`.draft` - a carrot for open science
====================================

`.draft` is a free cloud-based service that creates a PDF highlighting changes made to your `TeX` file. It's integrated with GitHub so that when you push changes or create a pull request, `.draft` will link to the PDF either by a commit comment or through the [GitHub Integrations API](https://github.com/integrations). In the (fierce) spirit of open-source science, `.draft` will only work on public GitHub repositories.

![Built at #dotastro](http://img.shields.io/badge/Built%20at-%23dotastro-blue.svg?style=flat)


Example
-------

[example gif showing how it works]


**Live demo** -- a link to a PR with this enabled.


How does it work?
-----------------

Once you've set up `.draft` to run on your repository, here's what happens:

0. GitHub will alert `.draft` when you push a commit or open a pull request

1. `.draft` will clone your repository

2. Unless your manuscript file is specified in a `.draft.yml` file in your repository, `.draft` will look for your LaTeX manuscript by finding the `*.tex` file that has been edited **most**

3. If the webhook was triggered by a pull request, the base (old) and head (new) versions of your manuscript are found by comparing branches. If the webhook was triggered by a commit, then by default the previous commit is considered the base. You can change this by specifying `[dd <sha/tag>]` in a commit message, and `.draft` will treat the SHA/tag given as the base for comparison.

4. A `latexdiff` is run against the base and head versions and a PDF is compiled that highlights the changes made

5. `.draft` comments back on the commit or pull request with a link to the compiled PDF


Setting up your repository with `.draft`
----------------------------------------

0.  In the "Settings" area of your GitHub repository, go to "Webhooks & services" then click the "Add webhook" button.

1.  Enter [`https://dotdraft.herokuapp.com`](https://dotdraft.herokuapp.com) as the Payload URL, select the "Send me *everything*" option, then click the green "Add webhook" button.

2.  That's it! Just commit a push to your repository or create a pull request, and `.draft` will do the rest.



Creating your own `.draft` app on Heroku
----------------------------------------
The standard `.draft` build will work for any public repository, but if you want to create your own then just follow the instructions in [`SETUP.md`](SETUP.md)



License
-------
Released under MIT license. For more information, see the [`LICENSE`](LICENSE) file. Copyright 2016 Andy Casey.
