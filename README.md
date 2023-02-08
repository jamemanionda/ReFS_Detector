# ReFS-DDWPᵇᵉᵗᵃ

*Data wiping tools Detector*

The Detector is ReFS $Logfile analysis tool. It allows for detecting data wiping tools behavior in log from Windows.

## Features

* Supports 12 Data Wiping tools Detection : EasyFileShredder, FileShredder, HardWipe, KernelFileShredder, PCShredder, RemoFileEraser, SecureEraser, SuperFileShredder, TurboShredder, WipeFile, xShredder, XTFileShredder
* Can extract opcode and metadata.
* Notify whether the tool was used.
* Notify the tool name when detect particular data wiping tools.
* Analysis for Directories and Files 


## Usage

This is gonna be a very basic guide for now.
![image](https://user-images.githubusercontent.com/50189201/217532655-2881d5e9-98d1-4c3d-b5b7-4e9fe18ec77a.png){: width="100" height="100"}


1. Get the $Logfile from ReFS.(If you experiment detecting wiping tools, you should delete files with data wiping tools in ReFS, first)
2. Use 'File pattern.py' for detecting file deletion and 'Directory pattern.py' for detecting directory deletion.
3. Open and Upload $Logfile
4. Starting Analysis
5. If Detecting particular data wiping tools, It notify the name of tools.


### FAQ

* Q: How do I report a bug?

  A: Please send me an email(jamemaniond@g.skku.edu). Please ensure that you respond to my inquiries as there's no other way I can fix bugs.


