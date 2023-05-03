# Small example project showing how to include out of tree updaters to Claircore

* Create all the necessary deps for libvuln (locker, store etc)
* Write an updater (Parse and Fetch)
* Add it to the libvuln.Options
* Run program, vulns should be be saved in a sqlite file called `db`
