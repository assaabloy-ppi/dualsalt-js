Automated testing environment (NodeJS + browsers)
===================

More than just unit tests here!

This subproject is integration of different popular JS tools and testing frameworks preconfigured as cross-platform environment for automated  `dualsalt-js` unit tests and testvectors test launches in both NodeJS and browser environments.

Used:
-----
* Karma (automated tests in browsers)
* Mocha + chai (unit testing)
* Browserify + brfs + watchify (makes server js code runnable in browser)

Quick start
--------

Run unit tests in NodeJS:

```npm run node-test```

Run unit tests in all browsers installed in system (autodetection):

```npm run browser-test```

 