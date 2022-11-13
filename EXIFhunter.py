'''
EXIFhunter v0.50
Bobby Price
n0mad-samurai
'''
'''
License: GPLv3
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY# without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

To view a copy of the GNU General Public License
visit: http://www.gnu.org/licenses/gpl.html
'''
'''
EXIFhunter automates the task of sifting through
a directory of files, to discover images that
contain possible Exchangeable Image File Format
(EXIF) metadata. Files are processed without
regard to file name extensions.
'''
'''
Python 3.x
'''
'''
EXIFhunter automates the task of sifting through
a directory of files, to discover images that
contain possible Exchangeable Image File Format
(EXIF) metadata. Files are processed without
regard to file name extensions.
'''
'''
Options include:
Save tabular results file (.txt) with
its forensic checksum (.sha1 default) file
Save csv results file (.csv) with
its forensic checksum (.sha1 default) file
Additional message digest selection for
checksum files: md5, sha256, and sha3 hashes
Verbose output that lists:
image types that it can recognize,
files that were not recognized as images,
images recognized by the process,
images that did not contain EXIF data,
images that contained comments.
'''
'''
Discovering forensically significant metadata in
non-descript images is time consuming.
Especially if images are mixed with other
non-descript files in a directory.
This program attempts to remove
the drudgery of that task.
'''
# import Python standard libraries
import os, sys      # os interfaces, system specific functions
import re           # regular expression operations
import cmd          # support for line-oriented command interpreters
import time         # time access and conversion
import hashlib      # secure hash and message digest algorithms
import imghdr       # determines the type of image contained in a file or byte stream
import argparse     # parser for command-line options, arguments and sub-commands

''' 
Import Optional PrettyTable Library
to install from the windows command line
or linux/mac terminal
pip install prettytable
'''
try:
    from prettytable import PrettyTable
    PRETTY = True

# if PrettyTable is
# not available
except:
    PRETTY = False
    
# Validate search path
def CheckInPath(inPath):
    
    # Validate input path
    # if not validated
    # exit program with error
    if not os.path.isdir(inPath):
        sys.exit('Path does not exist: '+inPath)
    
    # Validate input path is readable
    if not os.access(inPath, os.R_OK):
        sys.exit('Directory is not readable: '+inPath)
    
    # No errors
    else:
        return inPath   
    
# Validate save path   
def CheckOutPath(outPath):
    
    # Validate output path
    # if not validated
    # exit program with error
    if not os.path.isdir(outPath):
        sys.exit('Path does not exist: '+outPath)
    
    # Validate output path is writeable
    if not os.access(outPath, os.W_OK):
        sys.exit('Directory is not writeable: '+outPath)
    
    # No errors
    else:
        return outPath
    
# check and set message
# digest/hash algorithm
def SetHashObj(h):
    
    selection = ['md5','sha256','sha3']
    
    # catch wrong option selection and exit
    if not h in selection:
        print('sha1 is always the default')
        sys.exit('only use md5, sha256, or sha3, for -m')
    
    # set option selection
    if h == 'md5':
        setHash = hashlib.md5()
    elif h == 'sha256':
        setHash = hashlib.sha256()
    else:
        setHash = hashlib.sha3_256()
        
    return setHash

# create the process class
class HunterProcess():

    def __init__(self):
         
        # lists for capturing processed files
        self.fileList = []
        self.imageList = []
        self.noImageList = []
        self.exifList = []
        self.noExifList = []
        self.resultList = []
        self.commentsList = []

        # list of recognized image types
        self.IMAGE_TYPES = ['rgb','gif','pbm','pgm','ppm','tiff','rast','xbm','jpeg','bmp','png','webp','exr']

        # object index to 
        # aid formatting results
        self.NAM_NDX = 0
        self.TYP_NDX = 1
        self.SIZ_NDX = 2
        self.XIF_NDX = 3
        self.DIR_NDX = 4

        # initiate the cli method
        self.ParseCommandLine()

    # define the cli method
    def ParseCommandLine(self):
    
        # create an object to capture cli argument definitions
        parser = argparse.ArgumentParser('Python search for image files with possible EXIF data\n')
    
        # cli arguments for verbose option, directory to search, save csv results, save tablular results
        parser.add_argument('-v', '--verbose', help="option: displays recognized image types and additional file lists", action='store_true')
        parser.add_argument('-i', '--inDir', type= CheckInPath, required=True, help="required: directory/folder to search for EXIF data")
        parser.add_argument('-c', '--csvDir', type= CheckOutPath, required=False, help="option: directory/folder to save csv results")
        parser.add_argument('-t', '--txtDir', type= CheckOutPath, required=False, help="option: directory/folder to save tabular txt results")
        parser.add_argument('-m', '--msgDigest', type= SetHashObj, required=False, help="option: for a different hash value use md5, sha256, or sha3 (sha1 is always the default for result files)")
        
        # assign selected arguments to an object list
        args = parser.parse_args()

        # check args list for options
        # assign boolean results
        if args.verbose:
            self.VERBOSE = True
        else:
            self.VERBOSE = False
            
        if args.csvDir:
            self.CSV = True
        else:
            self.CSV = False
            
        if args.txtDir:
            self.TXT = True
        else:
            self.TXT = False
            
        # set the hash object
        if not args.msgDigest:
            self.hashObj = hashlib.sha1()
        else:
            self.hashObj = args.msgDigest

        # assign objects to the given directory arguments
        self.searchPath = args.inDir
        self.csvPath = args.csvDir
        self.txtPath = args.txtDir

    # Process files in the directory
    def ProcessFiles(self):

        # create the list of files
        count = 0
        for root, dirs, files in os.walk(self.searchPath):
            
            # separate filenames from path
            # and add those names to self.fileList
            for name in files:
                count += 1
                self.fileList.append(name)
            
            # exit program with error if directory is empty
            if count == 0:
                sys.exit('Directory is empty or files are hidden: '+root)

        # create the list of images
        for fname in self.fileList:
            
            '''
            Enable skip of my ghost file anomaly.
            If a recognized image in a sub-directory
            is used as a thumbnail for that
            sub-directory icon, the script will
            attempt to process that icon as if it
            were an image in the current directory.
            This produced a 'file does not exist' error.
            '''
            if os.path.exists(self.searchPath+'/'+fname):
                
                # identify images and add those to self.imageList
                if imghdr.what(self.searchPath+'/'+fname) in self.IMAGE_TYPES:
                    self.imageList.append(fname)
                else:
                    self.noImageList.append(fname)

        # parse self.imageList and
        # reconnect each image name
        # with its path
        for image in self.imageList:
            fullName = os.path.join(self.searchPath, image)
            
            # open fullName of image
            # as bytes for reading
            # assign to object f
            with open(fullName, 'rb') as f:
                
                # case insensitive search of
                # image object f for
                # byte string 'exif'
                exifFound = re.search(b'exif', f.read(), re.I)
            
            # if there is a result
            if exifFound:
                
                # get EXIF offset
                exifOffset = str(hex(exifFound.start()))
                
                # create list of images with EXIF data
                self.exifList.append(image)
                
                # get image size
                fSize = os.path.getsize(fullName)
                imageSize = str(fSize)
                
                # get image type
                imageType = imghdr.what(fullName)
                
                # create final result list tuple
                self.resultList.append([image,imageType,imageSize,exifOffset,self.searchPath])
            
            # if there is no result
            # add that image
            # to self.noExifList
            else:
                self.noExifList.append(image)
            
        # create list of images that may contain comments
        for image in self.imageList:
            fullName = os.path.join(self.searchPath, image)
            with open(fullName, 'rb') as f:
                
                # case sensitive search
                # for byte string 'File'
                commentsFound = re.search(b'File', f.read())
                
            if commentsFound:
                
                # create list of images with comments
                self.commentsList.append(image)
                    
        # verbose display option
        if self.VERBOSE:
                        
            # assign an object for OS cli options
            cli = cmd.Cmd()
            print('\nThe recognized image types are:')
            
            # display self.IMAGE_TYPES list in columns
            cli.columnize(self.IMAGE_TYPES, displaywidth=40)
            
            print('\nThese were not recognized as image files:')
            cli.columnize(self.noImageList, displaywidth=40)
            
            print('\nThese image files did not contain EXIF data:')
            cli.columnize(self.noExifList, displaywidth=40)
                
            print('\nThese image files may contain comments:')
            cli.columnize(self.commentsList, displaywidth=40)
            
        # all methods completed
        # with no errors
        return True

    # Display of results
    # with a column format
    # no prettytable!
    def DisplayResults(self):

        # display a message
        print('\nThese image files may contain EXIF data:')
        
        # create header object
        header = [['Image Name','Image Type','Image Size','EXIF Hex Offset','Search Path']]
        
        # create object that joins the header and self.resultList 
        dumpTable = header + self.resultList
        
        '''
        iterate through each element/column
        of each row of dumpTable, determine
        max width of each column, assign
        those values +3 to an object list
        '''
        widest_cols = [(max([len(str(row[i])) for row in dumpTable]) + 3) for i in range(len(dumpTable[0]))]
        
        # interate through column widths
        # using each column width, assign
        # that value to the row format list
        row_format = ''.join(["{:<" + str(widest_col) + "}" for widest_col in widest_cols])
            
        # display the table
        # by interating through
        # each row in dumpTable
        for row in dumpTable:
            
            # display all elements of each
            # row using the row_format
            print(row_format.format(*row))
            
    # Save results
    # with a column format
    # no prettytable!
    def SaveResults(self):
        
        # create header object list
        header = [['Image Name','Image Type','Image Size','EXIF Hex Offset','Search Path']]
        
        # create object list tuple that joins
        # the header and self.resultList 
        dumpTable = header + self.resultList
        
        '''
        iterate through each element/column
        of each row of dumpTable, determine
        max width of each column, assign
        those values +3 to an object list
        '''
        widest_cols = [(max([len(str(row[i])) for row in dumpTable]) + 3) for i in range(len(dumpTable[0]))]
        
        # interate through column widths
        # using each column width, assign
        # that value to the row format list
        row_format = ''.join(["{:<" + str(widest_col) + "}" for widest_col in widest_cols])
            
        # save txt file to the given directory
        try:
            # object contains full path to results file 'EhResults.txt'
            self.resultsText = self.txtPath+'/EhResults_np.txt'
            
            # assign object to handle results file write process
            with open(self.resultsText, 'w') as outFile:
                
                # write some messages to the results file
                outFile.write('Local System Type: '+sys.platform+'\n')
                outFile.write('Local System Time: '+time.ctime()+'\n')
                outFile.write('These image files may contain EXIF data:\n')
                
                # write the table to a file
                # by interating through
                # each row in dumpTable
                for row in dumpTable:
                    
                    # write all elements of each
                    # row using the row_format
                    outFile.write(row_format.format(*row)+'\n')
                
                # close the file/end the write process
                outFile.close
                
            # display a message
            print('\nText File: '+self.txtPath+'/EhResults_np.txt Created')
        
        # catch and display error if we cannot
        # open the results file for writing
        except Exception as err:
            print('Failed: Text File Save: '+str(err))                 
            
    # Pretty Table display of results
    def PrettyResultsDisplay(self):

        # Pretty Table Results
        # create table 't' with column headers
        t = PrettyTable(['Image Name','Image Type','Image Size','EXIF Hex Offset','Search Path'])

        # iterate through the list tuples in self.resultList
        # adding a row for each iteration/list tuple
        for r in self.resultList:
            t.add_row( [ r[self.NAM_NDX], r[self.TYP_NDX], r[self.SIZ_NDX], r[self.XIF_NDX], r[self.DIR_NDX] ] )

        # left align the table
        t.align = 'l'

        # get the whole table
        tabularResults = t.get_string()

        # display a message followed by the table
        print('\nThese image files may contain EXIF data:')
        print(tabularResults)    
    
    # Pretty Table Results save to file
    def PrettyResultsSave(self):

        # Pretty Table Results
        # create table 't' with column headers
        t = PrettyTable(['Image Name','Image Type','Image Size','EXIF Hex Offset','Search Path'])

        # iterate through the self.resultList
        # adding a row of data for each iteration        
        for r in self.resultList:
            t.add_row( [ r[self.NAM_NDX], r[self.TYP_NDX], r[self.SIZ_NDX], r[self.XIF_NDX], r[self.DIR_NDX] ] )

        # left align the table
        t.align = 'l'

        # get the whole table
        tabularResults = t.get_string()

        # save txt file to the given directory
        try:
            # object contains full path to results file 'EhResults.txt'
            self.resultsText = self.txtPath+'/EhResults.txt'
            
            # assign object to handle results file write process
            with open(self.resultsText, 'w') as outFile:
                
                # write some messages to the results file
                outFile.write('Local System Type: '+sys.platform+'\n')
                outFile.write('Local System Time: '+time.ctime()+'\n')
                outFile.write('These image files may contain EXIF data:\n')
                
                # write the table to the results file
                outFile.write(tabularResults)
                
                # close the file/end the write process
                outFile.close
                
            # display a message
            print('\nText File: '+self.txtPath+'/EhResults.txt Created')
        
        # catch and display error if we cannot
        # open the results file for writing
        except Exception as err:
            print('Failed: Text File Save: '+str(err))

    # CSV Results save to file
    def CsvResultsSave(self):
        
        # save csv file to the given directory
        try:
            # object contains full path to results file 'EhResults.csv'
            self.resultsCSV = self.csvPath+'/EhResults.csv'
            
            # assign object to handle results file write process
            with open(self.resultsCSV, 'w') as outFile:
                
                # write some messages to the results file
                outFile.write('Local System Type: '+sys.platform+'\n')
                outFile.write('Local System Time: '+time.ctime()+'\n')
                outFile.write('These image files may contain EXIF data:\n')                
                
                # create the column headings
                heading = 'Image Name'+','+'Image Type'+','+'Image Size'+','+'EXIF Hex Offset'+','+'Search Path'+'\n'
                
                # write the headings to the csv results file
                outFile.write(heading)
        
                for r in self.resultList:
                    outFile.write(r[self.NAM_NDX]+','+r[self.TYP_NDX]+','+r[self.SIZ_NDX]+','+r[self.XIF_NDX]+','+r[self.DIR_NDX]+'\n')
                    
                # close the file/end the write process
                outFile.close
            
            # display a message
            print('\nCSV File: '+self.csvPath+'/EhResults.csv Created')
        
        # catch and display error if we cannot
        # open the results file for writing        
        except Exception as err:
            print('Failed: CSV File Save: '+str(err))
            
    # save a checksum file with the
    # secure hash of txt results file
    def HashResultsTxt(self):
            
        # txt results file
        resultsFile = os.path.basename(self.resultsText)
        # checksum file
        digestFile = resultsFile + '.' + self.hashObj.name
        digestFilePath = self.txtPath+'/'+digestFile
            
            
        # compute the secure hash
        try:
            with open(self.resultsText, 'rb') as inpFile:
                
                if self.hashObj:
                
                    while True:  # process all blocks of the file
                        block = inpFile.read(1024)
                        if block:
                            self.hashObj.update(block)
                        else:
                            # once all blocks have been processed get the hash value
                            resultsDigest = self.hashObj.hexdigest().upper()
                            # no errors
                            lastError = ''
                            # exit the 'while' conditional loop
                            break
                    else:
                        resultsDigest = 'INVALID'
                        
        except Exception as err:
            
            # If errors occur report them
            lastError = '\nHashing Error: '+str(err)+'\n'
            print(lastError)
            
        # write the secure hash to
        # a checksum file including
        # name of txt results file
        try:
            
            with open(digestFilePath, 'w') as csumFile:
                csumFile.write(resultsDigest+' '+resultsFile)
                csumFile.close
            print('\twith SHA1 checksum file '+digestFile)
        
        except Exception as err:
            print('Failed: Checksum File Save: '+str(err))
            
    # save a file with the secure
    # hash of the csv results file
    def HashResultsCsv(self):

        # csv results file
        resultsFile = os.path.basename(self.resultsCSV)
        # checksum file
        digestFile = resultsFile + '.' + self.hashObj.name
        digestFilePath = self.csvPath+'/'+digestFile
        
        # compute the secure hash
        try:
            with open(self.resultsCSV, 'rb') as inpFile: 
                
                if self.hashObj:                

                    while True:  # process all blocks of the file
                        block = inpFile.read(1024)
                        if block:
                            self.hashObj.update(block)
                        
                        else:
                            # once all blocks have been processed get the hash value
                            resultsDigest = self.hashObj.hexdigest().upper()
                            # no errors
                            lastError = ''
                            # exit the 'while' conditional loop
                            break
                    else:
                        resultsDigest = 'INVALID'                    

        except Exception as err:
            # If errors occur report them
            lastError = '\nHashing Error: '+str(err)+'\n'
            print(lastError)

        # write the secure hash to
        # a checksum file including
        # name of csv results file
        try:

            with open(digestFilePath, 'w') as csumFile:
                csumFile.write(resultsDigest+' '+resultsFile)
                csumFile.close
            print('\twith SHA1 checksum file '+digestFile)
            
        except Exception as err:
            print('Failed: Checksum File Save: '+str(err))
    
# the main routine
if __name__ == '__main__':

    # capture start time
    startTime = time.time()
    
    VERSION = 'v0.50 October 2022'
    

    # instantiate the process class
    HunterObj = HunterProcess()

    print('\nWelcome to EXIFhunter '+VERSION)
    print('Local System Type: '+sys.platform)
    print('Local System Time: '+time.ctime())

    # Initiate process
    # if process fails
    # display aborted message
    # for any errors not specifically caught
    if HunterObj.ProcessFiles():
        
        if PRETTY:
            
            # if PrettyTable is
            # available, do this
            HunterObj.PrettyResultsDisplay()
                       
        # if no PrettyTable
        # do this instead            
        else:
            
            HunterObj.DisplayResults()
            
        if HunterObj.TXT:
                
            # if txt option selected
            # and if PrettyTable is
            # available, do this
            if PRETTY:
                HunterObj.PrettyResultsSave()
                HunterObj.HashResultsTxt()
                
            # if no PrettyTable
            # do this instead            
            else:
                HunterObj.SaveResults()
                HunterObj.HashResultsTxt()        
                
        if HunterObj.CSV:
            
            # if csv option
            # selected, do this            
            HunterObj.CsvResultsSave()
            HunterObj.HashResultsCsv()
         
        print('\nProgram completed normally')
        # capture end time
        endTime = time.time()
        # calculate duration
        duration = endTime - startTime
        # display elapsed time with 2 decimal places
        print('\nElapsed time:', '{:.2f}'.format(duration)+' seconds\n')
        
    else:
        
        print('Process Aborted!')
    


    
