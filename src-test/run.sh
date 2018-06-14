#!/bin/sh

browserify run-tests.js -o browsertests/bundle.js

while true; do
    read -p "Open browser? [y/n]: " yn
    case $yn in
        [Yy]* ) x-www-browser browsertests/index.html; break;;
        [Nn]* ) exit;;
        * ) echo "Please answer yes or no.";;
    esac
done
