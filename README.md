fastlaunch
==============================
fastlaunch is a ~~poorly written~~ command line based launcher.

Setup
------------------------------
* Download the latest release
* Run the executable
    * Import a configuration file if you have one
    * Find where `client.exe` is
    * Enter your first account (your first account defaults to the real device id unless specified when asked)
* Press the number that's the account then launch by pressing enter

"Compilation"
------------------------------
* Run `pip3 install pyinstaller` or get pyinstaller somehow
* Run `pyinstaller -F fastlauncher.py`
* Your executable is in `dist/`
