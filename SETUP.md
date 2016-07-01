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
