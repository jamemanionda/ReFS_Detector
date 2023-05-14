
# ᵇᵉᵗᵃ

*Data wiping tools Detector*

The Detector is ReFS $Logfile analysis tool. It allows for detecting data wiping tools behavior in $Logfile from Windows.

## Features

* Supports 12 Data Wiping tools Detection : EasyFileShredder, FileShredder, HardWipe, KernelFileShredder, PCShredder, RemoFileEraser, SecureEraser, SuperFileShredder, TurboShredder, WipeFile, xShredder, XTFileShredder
* Can extract opcode and metadata.
* Notify whether the tool was used.
* Notify the tool name when detect particular data wiping tools.
* Analysis for Directories and Files.

## Structure
<img src = "https://github.com/jamemanionda/ReFS_Detector/assets/50189201/95bb82fc-8719-432d-8984-49fce19fdba9" width="70%" height="70%">

## Usage

<img src = "https://user-images.githubusercontent.com/50189201/217536651-adf1c8ef-c362-4fd5-a9ab-4d7cbc4b242f.jpg" width="50%" height="50%">

1. Get the $Logfile from ReFS.(If you experiment detecting wiping tools, you should delete files with data wiping tools in ReFS first)
2. Use 'File pattern.py' for detecting file deletion and 'Directory pattern.py' for detecting directory deletion.
3. Open the detector and upload $Logfile.
4. Starting Analysis.
5. If Detecting particular data wiping tools, It notify the name of tools.

## ETC

### Sample
You can use sample $Logfile in '/Logfile Sample'.

### FAQ

* Q: How do I report a bug?

  A: Please send me an email. Please ensure that you respond to my inquiries as there's no other way I can fix bugs.


-----------
This is a tool developed for research purposes.

