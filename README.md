Firewall Script Generator
=========================

Generates a bash script containing advanced iptables rules.

Installation
------------

Move *firewall* to /usr/local/bin and make it executable

    mv firewall /usr/local/bin
    chmod +x /usr/local/bin/firewall

Move *firewall.base* to /etc/conf.d (the folder /etc/conf.d must exists).

    mv firewall /etc/conf.d

The generated file is created in /etc/conf.d/firewall.

In order to change this, edit the *firewall* file and change the value of *SCRIPT_FILE* variable.

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
