Firewall Script Generator
=========================

Generates a bash script containing advanced iptables rules in order to share internet connection with LAN users.

Installation
------------

Move *firewall.py* to /usr/local/bin/ and make it executable

    mv firewall /usr/local/bin/firewall
    chmod +x /usr/local/bin/firewall

Move *firewall.base* and *firewall.conf* to /etc/conf.d/.

    mv firewall.base firewall.conf /etc/conf.d/

Configuration
-------------

Modify the *firewall.conf* file

script.base : path to filerawall.base file
script.gen : path where script file to be executed will be generated

Munin related stuffs
--------------------

It's possible to bind this script with munin to generate graph per ip range.
In order to do so, copy the file *ip_* under the *munin_plugins* folder to your munin plugin folder (replace the old one).
Configure munin to use this plugin (this is not treated here).

Then activate Munin plugin in the *firewall.base* file by setting *MUNIN* variable to 1.
The variables *MUNIN_PLUGINS_PATH_FROM*, *MUNIN_PLUGINS_PATH_TO*, *MUNIN_NODE_RESTART_CMD* should be modified to fit your system.

Usage
-----

See `firewall -h` output.

License
-------

Copyright (C) 2011 by Joel Charles

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
