# Capastrophic!
Capastrophic is a Java Card toolkit designed specifically for training purposes. It enables parsing Java Card CAP and EXP files into JSON format, facilitates easy manipulation of the JSON representation of CAP files, and supports converting the modified JSON back into CAP files. Finally, it allows installation of these CAP files onto smart cards.

## Installation
Except for the `installer.py` tool, which requires the `pyscard` and `pycryptodome` libraries for communication with the card and implementing the SCP02/SCP03 protocols, respectively, all other tools in this project are developed solely using Python’s built-in features and do not depend on any external libraries.

> [!IMPORTANT]
> **Python 3.7 or newer is required.**
>
> The parser scripts rely on dictionary insertion order when generating JSON output.
> In versions of Python prior to 3.7, dictionaries do not guarantee element order, which may lead to incorrect or inconsistent analysis results.

> [!TIP]
> To install the required libraries, run:
>
> `pip install -r requirements.txt`

## Usage
**Parsing CAP and EXP Files**

The scripts `cap2json.py` and `exp2json.py` are used to generate JSON representations of CAP and EXP files, respectively. Output files are automatically saved in the output directory with filenames based on the input file name plus a timestamp. You can override the output path and filename by using the `-o` or `--output` option.

```
user@pc:~/capastrophic$ ./cap2json.py sample_files/helloworldPackage_2.3.cap
Parsed CAP file written to 'output/20250709_111232_helloworldPackage_2.3_cap.json'

user@pc:~/capastrophic$ ./exp2json.py sample_files/helloworldPackage_2.3.exp 
Parsed EXP file written to 'output/20250709_111241_helloworldPackage_2.3_exp.json'
```

Alternatively, use `-p` or `--print` to print the output directly to the command line.

```
user@pc:~/capastrophic$ ./cap2json.py -p sample_files/helloworldPackage_2.3.cap
{
  "Header.cap": {
    "raw": "01000fdecaffed0102040001054444444444",
    "raw_modified": "",
    "tag-u1": 1,
    "size-u2": 15,
    "magic-u4": "decaffed",
    "CAP_Format_version-u2": "2.1",
    "flags-u1": [
      "No-INT",
      "No-EXPORT",
      "APPLET",
      "No-EXTENDED"
    ],
    "package": {
      "version-u2": "1.0",
      "AID_length-u1": 5,
      "AID": "4444444444"
    }
  },
  "Directory.cap": {
    <...Truncated...>
```

**Note**: When `-p`/`--print` is used, an output file will be created only if `-o`/`--output` is explicitly specified; otherwise, the output is printed to the console only.

> [!TIP]
> Firefox includes a built-in JSON viewer with convenient features like "Fold All", "Expand All", and syntax highlighting. You can simply drag and drop the generated JSON files into Firefox to view a structured, user-friendly representation of their contents.

<p align="center">
  <img src="https://github.com/stillunfolding/capastrophic/blob/main/misc/firefox_json_viewer.png?raw=true" alt="Firefox JSON viewer" style="max-width: 100%; height: auto;">
</p>

**JSON Manipulation and CAP Generation**



## Supported CAP & EXP File Formats
Capastrophic supports all CAP and export file format versions introduced by Oracle as of today (July 2025):

- CAP and EXP file format 2.1
- CAP and EXP file format 2.2
- CAP and EXP file format 2.3
  - Compact Format
  - Extended Format

This ensures compatibility with a wide range of Java Card applets and JCVM implementations (i.e., Java Cards) for both analysis and deployment purposes.

A detailed mapping between Java Card versions and CAP/EXP file formats is provided in the table below.

    +------------------+-------------+-------------+
    |    Java Card     | .CAP Format | .EXP Format |
    +------------------+-------------+-------------+
    | JC 2.1           |         2.1 |         2.1 |
    +------------------+-------------+-------------+
    | JC 2.1.1         |         2.1 |         2.1 |
    +------------------+-------------+-------------+
    | JC 2.2           |         2.2 |         2.2 | <= Change
    +------------------+-------------+-------------+
    | JC 2.2.1         |         2.2 |         2.2 |
    +------------------+-------------+-------------+
    | JC 2.2.2         |         2.2 |         2.2 |
    +------------------+-------------+-------------+
    | JC 3.0.1 Classic |         2.2 |         2.2 |
    +------------------+-------------+-------------+
    | JC 3.0.4 Classic |         2.2 |         2.2 |
    +------------------+-------------+-------------+
    | JC 3.0.5 Classic |         2.2 |         2.2 |
    +------------------+-------------+-------------+
    | JC 3.1 Classic   |         2.3 |         2.3 | <= Change, + Extended Format Introduction
    +------------------+-------------+-------------+
    | JC 3.2 Classic   |         2.3 |         2.3 |
    +------------------+-------------+-------------+