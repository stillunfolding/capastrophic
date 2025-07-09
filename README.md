# [CAP]astrophic!
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

The generated JSON files from CAP files can be converted back into CAP format using the `json2cap.py` script. Before conversion, you may optionally modify the JSON files to alter the CAP file.

Two conversion modes are supported:

- **Shallow** mode (default): For each CAP component in the JSON, the script checks for the `raw_modified` field. If present **and non-empty**, its value is used to regenerate the CAP file. Otherwise, the original `raw` field is used. In this mode, the content of parsed elements (such as `size-u2`) is ignored.

- **Deep** mode: In this mode, the CAP file would be regenerated/reconstructed from the parsed fields (such as `size-u2`), rather than using raw byte values (`raw` or `raw_modified`).

> ⚠️ Note: Deep conversion mode is currently not implemented.

```
user@pc:~/capastrophic$ ./json2cap.py output/helloworld.json 
Added Header.cap
Added Directory.cap
Added Applet.cap
Added Import.cap
Added ConstantPool.cap
Added Class.cap
Added Method.cap
Added StaticField.cap
Added RefLocation.cap
Added Descriptor.cap
Generated CAP file is available under 'output/20250709_120026_helloworld_json.cap'
```

> [!TIP]
> To make CAP manipulation easier, the `raw_modified` field supports optional *commenting* and *formatting*. You may:
> - Use commenting characters: parentheses `()` or brackets `[]` to annotate or add comments. Both the grouping symbols **and the content inside them are removed before conversion**. 
> - Use separators: spaces, vertical bars `|`, angle brackets `<>` or commas to visually segment the hex string. Angle brackets can also enclose inline comments, but comments must be wrapped within valid grouping characters (see example below). All separator symbols and comments withing `<>` are removed during conversion, while the actual hex byte values remain unaffected.
> 
> **Example**
>
> ```{
>  "Header.cap": {
>    "raw": "01000fdecaffed0102040001054444444444",
>    "raw_modified": "01 000f decaffed 0102040001<(AID Len)05><(changing AID)5555555555>",
>    "tag-u1": 1,
>    "size-u2": 15
>    ...
>    ```
>
> This allows you to include helpful annotations without affecting parsing. However, note the following:
> - The content must still represent a valid hex string when grouping and separators are removed.
> - Newlines, quotation marks, and other characters that would break JSON syntax are not supported.

> [!IMPORTANT]
> Modifying the hex string (i.e., `raw_modified`) may have side effects.
For example, changing an AID to a shorter or longer value requires updating related fields, such as the component's `size` field part in the hex-string, to maintain consistency.
>
> Failing to do so (unless intentional) can result in corrupted CAP files or unexpected behavior during installation.
>
> Some off-card installers perform such consistency checks before installing a CAP file. However, the installer script provided in this project intentionally skips these checks and attempts to load the CAP file as is. This behavior is useful for training and testing purposes, where working with tampered CAP files is required.

> [!TIP]
> 🛠️ Working with `raw_modified` Field
>
> When manipulating the `raw_modified` field, it's important to understand which byte index corresponds to which actual component field in the CAP structure.
>
> To make this easier, the parsed fields within each component are named in a way that helps tracing their position in the raw byte array.
> 
> Specifically, fields with a fixed size include a suffix such as `-u1`, `-u2`, or `-u4` in their names, indicating that they occupy 1, 2, or 4 bytes, respectively, in the `raw` data.
> 
> This naming convention helps to accurately locate and modify specific elements in the raw binary representation.

**CAP Installation**

TBA

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

## To Do List
- Adding the `installer.py`
- Support for **Deep** mode CAP conversion