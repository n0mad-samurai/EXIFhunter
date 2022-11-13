# EXIFhunter

EXIFhunter automates the task of sifting through
a directory of files, to discover images that
contain possible Exchangeable Image File Format
(EXIF) metadata. Files are processed without
regard to file name extensions.

Options include:
Save tabular results file (.txt) with
its forensic checksum file (.sha1 default).
Save csv results file (.csv) with
its forensic checksum file (.sha1 default).
Additional message digest selection for
checksum files: md5, sha256, and sha3 hashes.
Verbose output that lists;
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

Basic output with PrettyTable

![basic output](screenshots/Eh_no-opt.png?raw=true "basic output")

Basic output with no PrettyTable

![no prettytable](screenshots/Eh_no_pretty.png?raw=true "no prettytable")

Verbose output

![verbose output](screenshots/Eh_v_nosave-opt.png?raw=true "verbose output")

Output that includes saving the results in a txt and CSV file

![saving results](screenshots/Eh_def_sha1.png?raw=true "saving results")
