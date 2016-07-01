`.draft` - a carrot for open science
==================================

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

3.  Add the TeX multipack so that we can run `latexdiff`. You will need to create a commit and push to Heroku to trigger a new build:

    ````
    heroku buildpacks:add git://github.com/holiture/heroku-buildpack-tex.git
    touch tmp
    git add tmp
    git commit -m "Trigger Heroku build"
    git push heroku master
    ````
