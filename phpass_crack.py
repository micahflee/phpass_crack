# phpass_crack
# Copyright 2010 Micah Lee <micahflee@gmail.com>
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import phpass
import sys
import threading
import Queue
import time
import datetime

# start timing the program
timing_start = datetime.datetime.now()

# global variables
output_filename = ''
userhashes = []
found_hashes = []
hashes_calculated = 0
stop = False

# the cracking thread
class Cracker(threading.Thread):
    def __init__(self, queue, verbose):
            threading.Thread.__init__(self)
            self.queue = queue
            self.verbose = verbose
    
    def run (self):
        global output_filename
        global userhashes
        global found_hashes
        global hashes_calculated
        global stop
        
        while True:
            if stop:
                break
            
            # grab user, passwd, and hash from the queue
            user, passwd, hash = self.queue.get()
            
            # hash it and compare results
            if phpass.crypt_private(passwd, hash) == hash:
                found_hash = '%s:%s' % (user, passwd)
                found_hashes.append(found_hash)
                
                # display success
                success = 'CRACKED: %s:%s' % (user, passwd)
                if self.verbose > 0:
                    print '\n%s' % success
                else:
                    print success
                
                # output to file -- I open and close the file each time so that the file gets written
                # to promptly, otherwise you can't tell if you've cracked a password sometimes until the 
                # whole program finishes
                if output_filename != '':
                    output_file = open(output_filename, "a")
                    output_file.write('%s:%s\n' % (user, passwd))
                    output_file.close()
                
                # stop everything if we found all the hashes
                if len(found_hashes) == len(userhashes):
                    if self.verbose > 0:
                        print '\n%d out of %d have been cracked, therefore quitting\n' % (len(found_hashes), len(userhashes))
                    stop = True
            hashes_calculated += 1
            
            # verbose
            if self.verbose == 1:
                sys.stdout.write('.')
            if self.verbose == 2:
                sys.stdout.write('%s ' % passwd)
            
            # all done
            self.queue.task_done()

# quit
def quit():
    global stop
    stop = True
    verbose = 0
    sys.stdout.write('\n\nWaiting for threads to end, please be patient')
    for i in range(7):
        sys.stdout.write('...')
        time.sleep(1)
    sys.stdout.write('\n\n')

# usage
def usage():
    print 'Usage: cat dict.txt | python phpass_crack.py <passwd file> [options]'
    print '  <passwd file>  A passwd file, each line a user:hash combination'
    print '  -v             Verbose - display dots for each hash'
    print '  -vv            Very verbose - display the current password for each hash'
    print '  -o file        Output file for cracked passwords'
    print '  -t threads     Number of simultaneous threads, defaults to 20'
    sys.exit()

if sys.stdin.isatty():
    print 'You need to pipe data into this program for it to work.\n'
    usage()

args = len(sys.argv)
if args < 2:
    usage()

# see about the options
verbose = 0
threads = 20
if args > 2:
    for i in range(2, args):
        if sys.argv[i] == '-v':
            verbose = 1
        if sys.argv[i] == '-vv':
            verbose = 2
        if sys.argv[i] == '-o':
            if args >= i+1:
                output_filename = sys.argv[i+1]
        if sys.argv[i] == '-t':
            if args >= i+1:
                threads = int(sys.argv[i+1])
                if threads == 0:
                    threads = 20

# if there's an output file, truncate it
if output_filename != '':
    output_file = open(output_filename, "w")
    output_file.close()

# prepare the list of hashes
passwd_file = open(sys.argv[1])
for line in passwd_file:
    line = line.strip()
    if ':' in line:
        user, hash = line.split(':')
        userhashes.append((user, hash))
passwd_file.close()
print 'Loaded %d hashes' % len(userhashes)
print 'Spawning %d threads' % threads
print ''

# start the threads
queue = Queue.Queue(0)
for i in range(threads):
    t = Cracker(queue, verbose)
    t.daemon = True
    t.start()

try:
    # do the cracking
    for passwd in sys.stdin:
        if stop == True:
            quit()
            break
        
        passwd = passwd.strip()
        
        # compare each hashed passwd with the current passwd
        for user, hash in userhashes:
            queue.put((user, passwd, hash))
    
    # if the stdin stream ends but the program isn't done cracking, let it keep doing its thing
    while queue.empty() == False:
        if stop == True:
            quit()
            break
except KeyboardInterrupt:
    quit()

# give the threads a chance to finish cleanly
if stop == False:
    quit()

# display the success at the end
print '\n\n%d hashes have been calculated' % hashes_calculated
print '%d hashes were inputed' % len(userhashes)
print '%d hashes were cracked' % len(found_hashes)

if len(found_hashes) > 0:
    print '\nCracked passwords:'
    for hash in found_hashes:
        print '  ', hash

# finish timing
timing_end = datetime.datetime.now()
timing_diff = timing_end - timing_start
minutes, seconds = divmod(timing_diff.seconds, 60)
hours, minutes = divmod(minutes, 60)
exection_time = 'Program executed in '
if timing_diff.days > 0:
    exection_time += '%d days, ' % timing_diff.days
if hours > 0:
    exection_time += '%d hours, ' % hours
if minutes > 0:
    exection_time += '%d minutes, ' % minutes
exection_time += '%d seconds ' % seconds
print '\n%s' % exection_time
sys.exit()
