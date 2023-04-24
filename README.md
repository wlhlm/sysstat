sysstat
=======

![Screenshot](sysstat-example.png)

This little program provides system status using the [i3bar protocol][i3bar]. I
wrote it as a replacement for a conky config I was previously using. This also
includes a "fuzzy" clock (toggleable by clicking on the i3bar).

Building/Installation
---------------------

Before building keep in mind that this program is intended for my personal needs
and thus might require some tweaks in the source code to fit _your_ needs. Some
options can be adjusted in `config.h` (requires recompilation). Simply build
`sysstat` with:

```bash
$ make
```
Dependencies
------------

- linux kernel (relies on data from /proc)
- libmpdclient
- yajl2

Ideas
-----

Some ideas I may implement at some point.

- extend `click_event` handling

License
-------

`sysstat` is licensed under a MIT license. For more details please see
the `LICENSE` file.


[i3bar]: http://i3wm.org/docs/i3bar-protocol.html
