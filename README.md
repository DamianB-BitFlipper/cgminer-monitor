Cgminer-Monitor and Commander
===============

Advanced monitor script for cgminer in python with console display, http server, email alerts. 
Enables cgminer to be controlled remotely without ssh. Uses encrypted emails with specific subjects and bodies to communicate from the commander script to the monitor script. This script is extremely configurable, allowing for every aspect to be modified to the user's liking.

Works on GNU/Linux, may need some modification to work on other platforms.

Tested with python 2.7.3 and cgminer 3.7.2.
Additional crypto modules may be needed.

Setup for extra modules:
   1. Install python-pip in order to install modules (replace apt-get with your distro installation manager)

         sudo apt-get install python-pip
   2. Install the python development headers needed to install the crypto modules

        sudo apt-get install python-dev
   3. Install crypto modules

         sudo pip install pycrypto
   4. Open cgminer-monitor.py in an editor and set the user configurations at the top
   5. Open cgminer-commander.py in an editor and set the user configurations at the top
   6. Start up the scripts using 'python [script name]'

## Usage for the Cgminer-Monitor Script ##

Script will need to open a socket, so super-user may be needed

In order for the script to use the cgminer's api, '--api-listen --api-allow W:127.0.0.1' must be included in the cgminer command or configuration file

Usage: python cgminer-monitor.py

 - Executes the monitor script

Usage: python cgminer-monitor.py [command] [parameter]

 - Executes a api command locally, direct access to the miner is needed

### Monitor mode ###
cgminer-monitor.py
 - Supports multi-gpu setups
 - Checks for incoming commands from the Commander script as a system for remote commanding of miner without ssh
 - Supports Email encryption for added security
 - Monitors cgminer by checking critical values
 - Emails if something is wrong
 - Checks the Internet connection periodically
 - Restarts cgminer if the GPU is sick or dead
 - Runs a dead simple http server that only serves a page with the results of the monitor (identical to the console output with a nice display)
 - Monitors MMFCE pools and display the current balance in their currencies
 - CTRL+C to stop the script
 - Extremely configurable allowing all aspects to be changed to the user's liking

### Command mode ###
cgminer-monitor.py [command] [optional parameter]
 - Outputs the results returned by cgminer miner and exits
 - Examples:
 	- cgminer-monitor.py summary
 	- cgminer-monitor.py gpu 0
 	- See cgminer's API-README for all available commands

## Usage for the Cgminer-Commander Script ##

Usage: python cgminer-commander.py [argument]
   --check or -c              Check for emails from the miner
   --send or -s                 Send a command email to the miner (Invokes built in text editor)
   --sendhelp or -sh     Ask miner for help information

 - If configured correctly, handles all of the formating and encryption of emails
 - When sending command emails, specific format must be followed
 - The commands are from cgminer's API, a list of the commands can be found in the API-README file
  * Format: command, parameter1, parameter2, etc;

        Example:

                        gpu, 0;

                        gpuintensity, 0, 13;

                        status;

                        quit;

  * API commands executed from top to bottom
  * Replies from cgminer's api will be emailed back

#### Credits ####
CGMinerClient class based on  WyseNynja's gist https://gist.github.com/WyseNynja/1500780
cgminer-monitor.py based on https://github.com/shazbits/cgminer-monitor

#### Official forum thread ####

### ISC License ##
https://github.com/JSmith-BitFlipper/cgminer-monitor/LICENSE.txt

Copyright (c) 2014, John Smith slimcoin@anche.no

### Donate ###
__BTC__ 1AsxJdSafUdES2HvAZt2pnF7DiPeunBRKn

__LTC__ LVD6egk3rF8se2xNgwGgvJfyvSBU8VV3nX

__PPC__ PTKehuReGEASb6EyUYj1V7JEMz5M6DdBBU

__DOGE__ DJwTG3P4jG8ujKvwfhBV6Bps39nriU5Ty4
