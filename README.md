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


Create your own `.draft` app on Heroku
--------------------------------------

0.  Login to heroku:

    `heroku login`

1.  Clone this repository:

    ````
    git clone git@github.com:andycasey/dotdraft.git dotdraft
    cd dotdraft/
    ````

2.  Create a Heroku app:

    `heroku create`

3.  Add the TeX multipack so that we can run `latexdiff`. 

    `heroku buildpacks:add git://github.com/holiture/heroku-buildpack-tex.git`

4.  Set the `HEROKU_URL` and `GH_TOKEN` environment variables in the Heroku app. You will need to create a GitHub token [from here](https://github.com/settings/tokens).

    ````
    heroku config:set HEROKU_URL=$(heroku info -s | grep web_url | cut -d= -f2)
    heroku config:set GH_TOKEN=my_token
    ````

5.  Push a new commit to Heroku to trigger a build.

    ````
    touch tmp
    git add tmp
    git commit -m "Trigger Heroku build"
    git push heroku master
    ````

6.  Now just follow the instructions in "Setting up your repository with `.draft`", except specify your own Heroku app URL.


License
-------
Released under MIT license. For more information, see the `LICENSE` file. Copyright 2016 Andy Casey.
