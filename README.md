# http_bruteforce
Script for Zeek, detects bruteforcing attempts in https traffic.

## Before using:
Configurate script for detecting attacks via POST requests, do this:
1. open http_bruteforce/hpbf.cfg.zeek
2. Add necessary keywords in fields "username" and "password"

## Using:
zeek -i <interface> http_bruteforce/[hpbf|hbbf]
