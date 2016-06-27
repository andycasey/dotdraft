`.draft` - a carrot for open science
==================================

Create your own `.draft` app on Heroku
--------------------------------------

0. Create a Heroku Python app that can run Flask.

1. Add the TeX multipack so that we can run `latexdiff`:

````
    heroku buildpacks:add git://github.com/holiture/heroku-buildpack-tex.git
````

