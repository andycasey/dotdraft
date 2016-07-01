`.draft` - a carrot for open science
====================================

`.draft` is a free cloud-based service that creates a PDF highlighting changes made to your `TeX` file. It's integrated with GitHub so that when you push changes or create a pull request, `.draft` will link to the PDF either by a commit comment or through the [GitHub Integrations API](https://github.com/integrations). In the (fierce) spirit of open-source science, `.draft` will only work on public GitHub repositories.

![Built at #dotastro](http://img.shields.io/badge/Built%20at-%23dotastro-blue.svg?style=flat)


Example
-------

[example gif showing how it works]


**Live demo** -- a link to a PR with this enabled.


Setting up your repository with `.draft`
----------------------------------------

0.  In the "Settings" area of your GitHub repository, go to "Webhooks & services" then click the "Add webhook" button.

1.  Enter `https://dotdraft.herokuapp.com` as the Payload URL, select the "Send me *everything*" option, then click the green "Add webhook" button.

2.  That's it! Just commit a push to your repository or create a pull request, and `.draft` will do the rest.


License
-------
Released under MIT license. For more information, see the `LICENSE` file. Copyright 2016 Andy Casey.
