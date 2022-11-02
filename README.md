# EXIFhunter
EXIFhunter automates the task of sifting through
a directory of files, to discover images that
contain possible Exchangeable Image File Format
(EXIF) metadata. Files are processed without
regard to file name extensions.

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

Discovering forensically significant metadata in
non-descript images is time consuming.
Especially if images are mixed with other
non-descript files in a directory.
This program attempts to remove
the drudgery of that task.

![alt text](screeshots/Eh_no-opt.png?raw=true "Basic output")
