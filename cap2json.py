#!/usr/bin/python3

import argparse
from datetime import datetime
import os
import json
from zipfile import ZipFile
from io import BytesIO, StringIO


def b2i(_bytes, endian="big"):
    return int.from_bytes(_bytes, endian)


def case_insensitive_get(dictionary, key, default=None):
    return next((v for k, v in dictionary.items() if k.lower() == key.lower()), default)


class NotSupported(Exception):
    def __init__(
        self, message="This CAP file includes a feature not supported by the parser!"
    ):
        super().__init__(message)


class CAP2JSON:
    """
    # JC EXP and CAP File Formats

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

    # CAP File Components

    component_compact {
        u1 tag
        u2 size
        u1 info[]
    }

    component_extended { (since CAP format 2.3)
        u1 tag
        u4 size         <= In some components, only the info[] element differs, while "size" remains u2.
        u1 info[]          IMO, The JCVM spec poorly names this struct as "extended", as we have few extended
    }                      components (ex. header, directory, etc.) in the form of above structure. A better
                           naming would be component_short_size and component_long_size: compact format
                           components always use the former, while extended format components use either,
                           depending on the component (see table below).

    +-------------------+---------+---------------+--------------------------+---------------+-------+
    |     Component     |   Tag   | Install Order |         Extension        |    Formats    | Size  |
    +-------------------+---------+---------------+--------------------------+---------------+-------+
    |       header      |    1    |     1 (M)     |           .cap           |      c/e      |   u2  |
    +-------------------+---------+---------------+--------------------------+---------------+-------+
    |     directory     |    2    |     2 (M)     |           .cap           |      c/e      |   u2  |
    +-------------------+---------+---------------+--------------------------+---------------+-------+
    |       applet      |    3    |    4 (Cond.)  |           .cap           |      c/e      |   u2  |
    +-------------------+---------+---------------+--------------------------+---------------+-------+
    |       import      |    4    |     3 (M)     |           .cap           | single format |   u2  |
    +-------------------+---------+---------------+--------------------------+---------------+-------+
    |    constantpool   |    5    |     9 (M)     |           .cap           | single format |   u2  |
    +-------------------+---------+---------------+--------------------------+---------------+-------+
    |       class       |    6    |     5 (M*)    |           .cap           |      c/e      |   u2  |
    +-------------------+---------+---------------+--------------------------+---------------+-------+
    |       method      |    7    |     6 (M)     |           .cap           |      c/e      | u2/u4 |
    |                   |         |               | .capx (only if extended) |               |       |
    +-------------------+---------+---------------+--------------------------+---------------+-------+
    |    staticField    |    8    |     7 (M)     |           .cap           | single format |   u2  |
    +-------------------+---------+---------------+--------------------------+---------------+-------+
    | referenceLocation |    9    |    10 (M*)    |           .cap           |      c/e      | u2/u4 |
    |                   |         |               | .capx (only if extended) |               |       |
    +-------------------+---------+---------------+--------------------------+---------------+-------+
    |       export      |    10   |    8 (Cond.)  |           .cap           |      c/e      |   u2  |
    +-------------------+---------+---------------+--------------------------+---------------+-------+
    |     descriptor    |    11   |    12 (M*)    |           .cap           |      c/e      | u2/u4 |  <== Mandatory in CAP file, but optionally is loaded!
    |                   |         |               | .capx (only if extended) |               |       |
    +-------------------+---------+---------------+--------------------------+---------------+-------+
    |       debug       |    12   |Offcard (Opt.) |        .cap/.capx        |      c/e      | u2/u4 |  <== Since CAP format 2.2
    +-------------------+---------+---------------+--------------------------+---------------+-------+
    |  staticResources  |    13   |   11 (Cond.)  |           .capx          | single format |   u4  |  <== Since CAP format 2.3
    +-------------------+---------+---------------+--------------------------+---------------+-------+
    |   custom[0-128]   | 128-255 |      ...      |        .cap/.capx        |       -       |   -   |
    +-------------------+---------+---------------+--------------------------+---------------+-------+
    c: compact
    e: extended
    *: For the components Class, ReferenceLocation, and Descriptor, the specificaiton does not clearly state whether they are mandatory or conditional/optional.
       Per information in Section 6.5 "Directory Info", for all the components other than Applet, Export, Debug, and StaticResources, the respective component
       size in the component_sizes array, shall be greater than zero, making the components subject of this comment, Mandatory. Additionally, in Section 6.2
       "Component Model", optional components are listed, and they are limited to Applet, Export, Debug, and StaticResources. However, per the definition of the
       "CAP file component" in Appendix B, in which the "Required" components are listed, these three (Class, ReferenceLocation, and Descriptor), are neither "Required",
       and nor listed in the optional/conditional components listed in the next paragraph of the same section.
    + When the flags in the header component indicate an extended format, then, per JCVM spec, Method, Descriptor, RefLoc, Debug, and all custom components must
      be in extended format; however, for other components, it says nothing.
    **********************************

    # Inter-Component References:

    +----------------------+--------------------------------+-------------------------------+
    |  Components (X)      |     X Referenced By (<==)      |       X Refers to (==>)       |
    +----------------------+--------------------------------+-------------------------------+
    |  [Header]            | [None]                         | [None]                        | # But specifies characterstics/format and absense/presence of few other components.
    +----------------------+--------------------------------+-------------------------------+
    |  [Directory]         | [None]                         | [None]                        | # But there are consistency relations with multiple other components.
    +----------------------+--------------------------------+-------------------------------+
    |  [Applet]            | [None]                         | [Method]                      | # For install_method_offsets
    +----------------------+--------------------------------+-------------------------------+
    |  [Import]            | [ConstantPool]                 | [None]                        | # For package_token in case of external references
    +----------------------+--------------------------------+-------------------------------+
    |  [ConstantPool]      | [Class], [Method]              | [Class], [StaticFiled],       | # + consistency relation with [Descriptor]
    |                      |                                | [Method], [Import]            |
    +----------------------+--------------------------------+-------------------------------+
    |  [Class]             | [...]                          | [...]                         |
    +----------------------+--------------------------------+-------------------------------+
    |                      | [Applet], [ConstantPool],      |                               |
    |  [Method]            | [Export], [Descriptor],        | [ConstantPool]                |
    |                      | [Debug], [ReferenceLocation],  |                               |
    |                      | [Class]                        |                               |
    +----------------------+--------------------------------+-------------------------------+
    |  [StaticField]       | [ConstantPool], [Export],      | [None]                        | # These four components reference the fields in the statif field image defined
    |                      | [Descriptor], [Debug]          |                               | # by the Static Field Component. Offsets, are offsets to the image, not to the component
    +----------------------+--------------------------------+-------------------------------+
    |  [ReferenceLocation] | [None]                         | [Method]                      | # for offsets of Method component that have references to Constant Pool
    +----------------------+--------------------------------+-------------------------------+
    |  [export]            | [None]                         | [Class], [StaticField],       |
    |                      |                                | [Method]                      |
    +----------------------+--------------------------------+-------------------------------+
    |  [Descriptor]        | [None]                         | [Class], [StaticField],       |
    |                      |                                | [Method], [ConstantPool]      |
    +----------------------+--------------------------------+-------------------------------+
    |  [Debug]             | [None]                         | [Class], [StaticField]        | # We don't care about this one, as it is not loaded into the card.
    |                      |                                | [Method]                      |
    +----------------------+--------------------------------+-------------------------------+
    |  [StaticResources]   | [None!]                        | [None]                        | # so how this resources are used?!
    +----------------------+--------------------------------+-------------------------------+

    * The text in the first paragraph of Section 6.5 "Directory Component" indirectly implies that Static Resources component is only for
      the Extended format CAP files, however, per component_size_info_compact, and component_size_info_extended, this component can be present
      for both formats (starting from CAP format 2.3). Nevertheless, given that [apparantly] no other component refers to this component, it
      is not clear to me how the contents are going to be used!

    **********************************

    # CAPFile Structure (compact):

    ===============> Header.cap/c
    % notes:
        - General information about this CAP file and the "public" packages it defines.
        - A change in the major version number of CAP format indicates a major incompatibility change,
          one that requires a fundamentally different Java Card virtual machine.
        - flags
            - ACC_EXPORT => Export Component is included in this CAP file. Otherwise it has the value of 0.
            - ACC_APPLET => Applet Component is included in this CAP file. Otherwise it has the value of 0.
            - ACC_EXTENDED =>  Method Component, Reference Location component, Descriptor Component, Debug
              Component and all custom components in the CAP file must be in the Extended Format. Otherwise
              it has the value of 0.
        - package_name: absent if the package does not define any remote interfaces or remote classes

    % structure:
    | header_component_compact {
    |   u1  tag
    |   u2  size
    |   u4  magic
    |
    |   u1  CAP_Format_minor_version
    |   u1  CAP_Format_major_version
    |
    |   u1  flags                           #consistency
    |
    |   package_info package
    |   package_name_info package_name ----> (since CAP File format 2.2)
    | }

        | package_info {
        |   u1 minor_version
        |   u1 major_version
        |   u1 AID_length
        |   u1 AID[AID_length]
        | }

        | package_name_info { (since CAP format 2.2)
        |   u1 name_length
        |   u1 name[name_length]
        | }


    ===============> Directory.cap/c
    % notes:
        - When an optional or a conditional component is absent, respective size is set to zero
            + optional/conditional components: applet, export, debug, static_resourses
            + for all the other components, size shall be higher than zero
            + Note that while "Descriptor" component is not an optional component in the cap file,
              loading it into the card during load process is "optional".
        - Each custom component has an AID that represents the JC platform name of the component.
          its size has to be in range [5,16], inclusive.

    % structure:
    | directory_component_compact {
    |   u1  tag
    |   u2  size
    |   component_size_info_compact  component_sizes
    |   static_field_size_info  static_field_size
    |   u1  import_count                            <= Same value as what we have in Import Component #consistency
    |   u1  applet_count                            <= Same value as what we have in Applet Component #consistency
    |   u1  custom_count                            <= in range [0, 127], inclusive
    |   custom_component_info_compact  custom_components[custom_count]
    | }

        | component_size_info_compact { #consistency
        |   u2  Header_Component_Size
        |   u2  Directory_Component_Size
        |   u2  Applet_Component_Size
        |   u2  Import_Component_Size
        |   u2  Constant_Pool_Component_Size
        |   u2  Class_Component_Size
        |   u2  Method_Component_Size
        |   u2  Static_Field_Component_Size
        |   u2  Reference_Location_Component_Size
        |   u2  Export_Component_Size
        |   u2  Descriptor_Component_Size
        |   u2  Debug_Component_Size (since CAP format 2.2)
        |   u4  Static_Resource_Component_Size (since CAP format 2.3)
        | }

        | static_field_size_info {      <= First two items are equal with equivalen items in StaticField compoent. #consistency
        |   u2  image_size              <= Total number of bytes in the static fields defined in all packages in this CAP file, excluding
        |                                  final static fields of primitive types. (for references and arrays, 2 byte per each)
        |   u2  array_init_count        <= The number of arrays initialized in all of the <clinit> methods in all the packages in this CAP file.
        |   u2  array_init_size         <= The sum of the count items in the array_init table item of the Static Field Component. It is the
        | }                                total number of bytes in all of the arrays initialized in all of the <clinit> methods in all the
                                           packages in this CAP file.


        | custom_component_info_compact {
        |   u1  component_tag           <= in range [128, 255], inclusive
        |   u2  size
        |   u1  AID_length
        |   u1  AID[AID_length]
        | }


    ===============> Applet.cap/c
    % notes:
        - If no applets are defined by any of the packages in this CAP file, this component must not
          be present in this CAP file.
        - The RID (first 5 bytes) of all of the applet AIDs must have the same value.
        - For each applet, install_method_offset item, must be a 16-bit offset into the info item of
          the Method Component (for extended cap: into the method_component_block in the blocks array of Method Component)
        - The install(byte[],short,byte) method must be defined in a class that extends the
          javacard.framework.Applet class, directly or indirectly

    % structure
    | applet_component_compact {
    |   u1 tag
    |   u2 size
    |   u1 count
    |   {
    |     u1  AID_length
    |     u1  AID[AID_length]
    |     u2  install_method_offset
    |   } applets[count]
    | }


    ===============> Import.cap
    % notes:
        - Contains an entry for each of the packages referenced in the CAP file
        - Does not include the packages defined in this CAP file.
        - Components of this CAP file refer to an imported package by using an index
          in this packages table. The index is called a package token.

    % structure:
    | import_component_compact {
    |   u1  tag
    |   u2  size
    |   u1  count
    |   package_info  packages[count]
    | }

        | package_info {
        |   u1 minor_version
        |   u1 major_version
        |   u1 AID_length
        |   u1 AID[AID_length]
        | }


    ===============> ConstantPool.cap
    % notes:
        - It contains an entry for each of the classes, methods, and fields referenced by elements in the Method
          Component. The referencing  elements in the Method Component may be instructions in the methods or exception
          handler catch types in the exception handler table.
        - Entries in this component do not reference other entries internal to itself.
        - Java Card platform constant types (“Java Card constant types”) are more specific than those in Java class
          files. The categories indicate not only the type of the item referenced, but also the manner in which it is
          referenced. For example, while in the Java constant pool there is one constant type for method references,
          in the Java Card platform constant pool there are three constant types for method references:
          + one for virtual method invocations using the invokevirtual bytecode,
          + one for super method invocations using the invokespecial bytecode,
          + and one for static method invocations using either the invokestatic or invokespecial bytecode.*
          (* The constant pool index parameter of an invokespecial bytecode is to a CONSTANT_ StaticMethodref when the
           method referenced is a constructor or a private instance method. In these cases the method invoked is fully known
           when the CAP file is created. In the cases of virtual method and super method references, the method invoked is
           dependent upon an instance of a class and its hierarchy, both of which may be partially unknown when the CAP
           file is created.)
          The additional information provided by a constant type in Java Card technologies simplifies resolution of references.
        - There are no ordering constraints on constant pool entries.  It is recommended, however, that CONSTANT_InstanceFieldref
          constants occur early in the array to permit using getfield_T and putfield_T bytecodes instead of getfield_T_w and
          putfield_T_w bytecodes. <= they have different respectively 1-byte-width and 2-bytes-width operand lengths.
        - The first entry in the constant pool cannot be an exception handler class that is referenced by a
          catch_type_index of an exception_handler_info structure. In such a case the value of the
          catch_type_index would be equal to 0, but the value of 0 in a catch_type_index is reserved
          to indicate an exception_handler_info structure that describes a finally block.

    % structure:
    | constant_pool_component {
    |   u1  tag
    |   u2  size
    |   u2  count
    |   cp_info  constant_pool[count]
    | }

        | cp_info {
        |   u1 tag       ----> 1: Classref, 2: InstanceFieldref, 3: VirtualMethodref, 4: SuperMethodref, 5: StaticFieldref, 6: StaticMethodref
        |   u1 info[3]
        | }


            | CONSTANT_Classref_info {      <= for both classes and interfaces
            |   u1 tag
            |   union {
            |     u2 internal_class_ref     <= 16-bit offset into the "info" item of Class Component; 0 < and =< 32767
            |     {
            |       u1 package_token        # =< 127; high bit is equal to one.
            |       u1 class_token          # Per imported package export file
            |     } external_class_ref
            |   } class_ref
            |   u1 padding
            | }


            | CONSTANT_InstanceFieldref_info {
            |   u1 tag
            |   class_ref class              # the class associated with the referenced instance field
            |   u1 token
            | }


            | CONSTANT_VirtualMethodref_info {
            |   u1 tag
            |   class_ref class             # the class associated with the referenced virtual method
            |   u1 token                    # "public" or "protected" method? => the high bit of the token item is zero.
            | }                             # If the referenced method is package-visible the high bit of the token item is one.
                                            # In this case the class item must represent a reference to a class defined in this package.

            | CONSTANT_SuperMethodref_info {
            |   u1 tag
            |   class_ref class             # the class associated with the referenced super method
            |   u1 token                    # "public" or "protected" method? => the high bit of the token item is zero.
            | }                             # If the referenced method is package-visible the high bit of the token item is one.
                                            # In the latter case the class item must represent a reference to a class defined in this package
                                            # and at least one superclass of the class that contains a definition of the virtual method must
                                            # also be defined in this package.

            | CONSTANT_StaticFieldref_info {
            |   u1 tag
            |   union {
            |     { u1 padding
            |       u2 offset                <= 16-bit offset into the Static Field Image defined by the Static Field component to this static field
            |     } internal_ref
            |     { u1 package_token        # =< 127; high bit is equal to one.
            |       u1 class_token
            |       u1 token
            |     } external_ref
            |   } static_field_ref
            | }

            | CONSTANT_StaticMethodref_info {   # includes references to static methods, constructors, and private virtual methods.
            |   u1 tag
            |   union {
            |     { u1 method_info_block_index (since CAP format 2.3)
            |       u2 offset               <= 16-bit offset into the info item of the Method component to a to a method_info structure
            |     } internal_ref
            |     { u1 package_token        # =< 127; high bit is equal to one.
            |       u1 class_token
            |       u1 token
            |     } external_ref
            |   } static_method_ref
            | }


    ===============> Class.cap/c
    % notes:
        - todo

    % structure:
    | class_component_compact {
    |   u1  tag
    |   u2  size
    |   u2  signature_pool_length (since CAP format 2.2)
    |   type_descriptor  signature_pool[](since CAP format 2.2)
    |   interface_info  interfaces[]
    |   class_info_compact  classes[]
    | }

        | type_descriptor { (since CAP format 2.2)
        |   u1 nibble_count;
        |   u1 type[(nibble_count+1) / 2];
        | }


        | interface_info {
        |   u1 bitfield {
        |     bit[4] flags
        |     bit[4] interface_count                    <= valid values are [0,1,..,14]
        |   }
        |   class_ref superinterfaces[interface_count]  <= direct or indirect supper interfaces
        |   interface_name_info interface_name          <= Only in case ACC_REMOTE is in the flags
        | }

            | interface_name_info {
            |   u1 interface_name_length
            |   u1 interface_name[interface_name_length]
            | }


        | class_info_compact {
        |   u1 bitfield {
        |     bit[4] flags
        |     bit[4] interface_count                    <= interfaces implemented by this class, including super interfaces of the interface
        |   }                                              and potentially, interfaces implemented by super class of this class.
        |   class_ref super_class_ref
        |   u1 declared_instance_size
        |   u1 first_reference_token
        |   u1 reference_count
        |   u1 public_method_table_base
        |   u1 public_method_table_count
        |   u1 package_method_table_base
        |   u1 package_method_table_count
        |   u2 public_virtual_method_table[public_method_table_count]
        |   u2 package_virtual_method_table[package_method_table_count]
        |   implemented_interface_info interfaces[interface_count]
        |   remote_interface_info remote_interfaces (since CAP format 2.2)      <= Only in case ACC_REMOTE is in the flags
        |   u1 public_virtual_method_token_mapping[public_method_count] (since CAP format 2.3)
        |   u1 CAP22_inheritable_public_method_token_count (since CAP format 2.3)
        | }

            | implemented_interface_info {
            |   class_ref interface
            |   u1 count
            |   u1 index[count]
            | }

            | remote_interface_info { (since CAP format 2.2)
            |   u1 remote_methods_count
            |   remote_method_info remote_methods[remote_methods_count]
            |   u1 hash_modifier_length
            |   u1 hash_modifier[hash_modifier_length]
            |   u1 class_name_length
            |   u1 class_name[class_name_length]
            |   u1 remote_interfaces_count
            |   class_ref remote_interfaces[remote_interfaces_count]
            | }

                | remote_method_info { (since CAP format 2.2)
                |   u2 remote_method_hash
                |   u2 signature_offset
                |   u1 virtual_method_token
                | }


    ===============> Method.cap/c
    % note:
        - The Method Component describes each of the methods declared in this CAP file, excluding <clinit>
          methods and interface method declarations. Abstract methods defined by classes (not interfaces) are
          included. The exception handlers associated with each method are also described.
        - The Method Component does not contain complete access information and descriptive details for each
          method. Instead, the information is optimized for size and therefore limited to that required to execute
          each method without performing verification. Complete details regarding the methods defined in this
          package are included in the Descriptor Component.
        - Among other information, the Descriptor Component contains the location and number of bytecodes for
          each method in the Method Component. This information can be used to parse the methods in the Method
          Component.
        - Instructions and exception handler catch types in the Method Component reference entries in the
          Constant Pool Component. No other CAP file components, including the Method Component, are referenced
          by the elements in the Method Component.
        - Entries in the exception_handlers array are sorted in ascending order by the offset to the handler
          of the exception handler. Smaller offset values occur first in the array. This ordering constraint ensures
          that the first match found when searching for an exception handler is the correct match.
          There are two consequences of this ordering constraint. First, a handler that is nested with the active
          range (try block) of another handler occurs first in the array. Second, when multiple handlers are
          associated with the same active range, they are ordered as they occur in a method. This is consistent
          with the ordering constraints defined for Java class files.
        - The methods item represents a table of variable-length method_info structures. Each entry
          represents a method declared in a class of this package. <clinit> methods and interface method
          declaration are not included; all other methods, including non-interface abstract methods, are.
        - The stop_bit item indicates whether the active range (try block) of this exception handler is
          contained within or is equal to the active range of any succeeding exception_handler_info
          structures in this exception_handlers array. At the Java source level, this indicates whether an
          active range is nested within another, or has at least one succeeding exception handler associated with
          the same range. The latter occurs when there is at least one succeeding catch block or a finally block.
          The stop_bit provides an optimization to be used during the interpretation of the athrow bytecode.
        - The impdep1 and impdep2 bytecodes cannot be present in the bytecodes array item.

    % structure:
    | method_component_compact {
    |   u1 tag
    |   u2 size
    |   u1 handler_count
    |   exception_handler_info exception_handlers[handler_count]
    |   method_info methods[]
    | }

        | exception_handler_info {
        |   u2 start_offset
        |   u2 bitfield {
        |     bit[1] stop_bit
        |     bit[15] active_length
        |   }
        |   u2 handler_offset
        |   u2 catch_type_index
        | }

        | method_info {
        |   method_header_info method_header
        |   u1 bytecodes[]
        | }

            | method_header_info {
            |   u1 bitfield {
            |     bit[4] flags
            |     bit[4] max_stack
            |   }
            |   u1 bitfield {
            |     bit[4] nargs
            |     bit[4] max_locals
            |   }
            | }

            | extended_method_header_info {
            |   u1 bitfield {
            |     bit[4] flags
            |     bit[4] padding
            |   }
            |   u1 max_stack
            |   u1 nargs
            |   u1 max_locals
            | }


    ===============> StaticField.cap
    % notes:
        - contains all of the information required to create and initialize an image of all of the static fields
          defined in this CAP file, referred to as the static field image.
        - Offsets to particular static fields are offsets into the static field image, not the Static Field Component.
        - Final static fields of primitive types are not represented in the static field image. Instead these compile-
          time constants must be placed in line in Java Card technology-based instructions
        - The Static Field Component includes all information required to initialize classes. In the Java virtual
          machine a class is initialized by executing its <clinit> method. In the Java Card virtual machine the
          functionality of <clinit> methods is represented in the Static Field Component as array initialization
          data and non-default values of primitive types data.
        - Reference types occur first in the image. Arrays initialized through Java <clinit> methods occur first
          within the set of reference types. Primitive types occur last in the image, and primitive types initialized
          to non-default values occur last within the set of primitive types.


        - Segments of a Static Field Image:
                Category       Segment       Content
            ________________|__________|_____________________________________________________
            reference types |    1     | arrays of primitive types initialized by <clinit> methods
            reference types |    2     | initialized to null, including arrays
            primitive types |    3     | initialized to default values
            primitive types |    4     | initialized to non-default values

        - The image_size item indicates the number of bytes required to represent the static fields defined in this
          CAP file, excluding final static fields of primitive types. This value is the number of bytes in the static
          field image.
        - The value of the image_size item does not include the number of bytes required to represent the
          initial values of array instances enumerated in the Static Field Component.
        - image_size =  reference_count * 2 +
                        default_value_count +
                        non_default_value_count.
        - The reference_count item indicates the number of reference type static fields defined in this CAP file.
          This is the number of fields represented in segments 1 and 2 of the static field image
        - The array_init_count item indicates the number of elements in the array_init array. This is
          the number of fields represented in segment 1 of the static field image. It represents the number of
          arrays initialized in all of the <clinit> methods in this CAP file.
        - If this CAP file defines a library package the value of array_init_count must be zero.
        - The array_init item represents an array that specify the initial array values of static fields of arrays
          of primitive types. These initial values are indicated in Java <clinit> methods.


    % structure:
    | static_field_component {
    |   u1 tag
    |   u2 size
    |   u2 image_size
    |   u2 reference_count                              <= Segment #1 and #2 of Static Field Image
    |   u2 array_init_count
    |   array_init_info array_init[array_init_count]
    |   u2 default_value_count                          <= Segment #3 of Static Field Image
    |   u2 non_default_value_count                      <= Segment #4 of Static Filed Image
    |   u1 non_default_values[non_default_values_count]
    | }

        | array_init_info {
        |   u1 type             <= Boolean=2, Byte, Short, Int=5
        |   u2 count            <= number of "bytes" in the values array, is not necessarily equal with
        |                          the number of elements in the static array (due to different type-lengths)
        |   u1 values[count]    <= a byte array containing the initial values of the static field array.
        | }


    ===============> RefLocation.cap/c
    % notes:
        - This component contains two lists of offsets for the "info" item of the Method component that
          contain indices of the constant_pool array of ConstantPool component. This includes:
            - all constant pool index operands of instructions
            - all non-zero catch_type_index items of the exception_handlers array
                - The catch_type_index items that have the value of 0 are not included since
                  they represent finally blocks instead of particular exception classes.
        - Some of the constant pool indices are represented in one-byte values while others are represented
          in two-byte values. Operands of getfield_T and putfield_T instructions are one-byte constant pool
          indices. All other indices in a Method Component are two-byte values.

    % structure:
    | reference_location_component_compact {
    |   u1 tag
    |   u2 size                         <= Must be > 0
    |   u2 byte_index_count
    |   u1 offsets_to_byte_indices[byte_index_count]        <=  1-byte jump offsets into the info item of the Method Component
    |   u2 byte2_index_count                                    to each 1-byte constant_pool[] array index.
    |   u1 offsets_to_byte2_indices[byte2_index_count]      <=  1-byte jump offsets into the info item of the Method Component
    | }                                                         to each 2-byte constant_pool[] array index.


    ===============> Export.cap/c
    % notes:
        - Lists all the static elements in the CAP file that may be imported
          by classes in other packages
        - Instance fields and virtual methods are not represented
        - For extended CAP files, no information of the private packages
        - For compact CAP files, presence of this component means a public package
        - For public packages that include "applets" (flags in Header component),
          Export component includes entries only for the "public" interfaces that are
          Shareable.
            - An interface is shareable if and only if it is the javacard.framework.Shareable
              interface or implements (directly or indirectly) that interface.
        - For public pakcages that do not include any applet, the Export component
          contains:
            - an entry for each public class and public interface.
            - an entry for each public or protected static field of public classes
            - an entry for each public or protected static method of public classes,
            - an entry for each public or protected constructor of public class.
            - Final static fields of primitive types (compile-time constants) are not includeds
        - The table "class_exports[]" contains entries for externally accessible classes or interfaces.
          An index into the table to a particular class or interface is equal to the token value of that class or
          interface. The token value is published in the Export file of the package containing the class.
        - class_offset: represents a byte offset into the info item of the Class Component.
            - For library CAP files: the item at that offset must be either an interface_info or a
              class_info structure. The interface_info or class_info structure at that offset must
              represent the exported class or interface.
            - For application CAP files, the item at the class_offset in the info item of the Class Component
              must be an interface_info structure. The interface_info structure at that offset must
              represent the exported, shareable interface. In particular, the ACC_SHAREABLE flag of the
              interface_info structure must be equal to 1.
        - static_field_offsets: represents an array of 2-byte offsets into the static field image defined
          by the Static Field Component. Each offset must be to the beginning of the representation of the
          exported static field. An index into the static_field_offsets array must be equal to the token value
          of the field represented by that entry. The token value is published in the Export file of this package.
        - The static_method_offsets item represents a table of 2-byte offsets into the info item of the
          Method Component. Each offset must be to the beginning of a method_info structure. The method_info
          structure must represent the exported static method or constructor. An index into the static_method_offsets
          array must be equal to the token value of the method represented by that entry.
        - If the class_offset item represents an offset to an interface_info structure, the value of the
          static_method_count item must be zero.


    % structure:
    | export_component_compact {
    |   u1 tag
    |   u2 size
    |   u1 class_count                      <== Must be > 0, otherwise, this component in not expected
    |   class_export_info {
    |     u2 class_offset
    |     u1 static_field_count             |<==  number of public/protected static fields (excluding final static fields
    |     u1 static_method_count            |     of primitive types),  and public/protected static methods and constructors
    |                                       |     defined in this class. For interfaces, both are zero.
    |
    |     u2 static_field_offsets[static_field_count]       <== offsets to the static field image of StaticField Component.
    |     u2 static_method_offsets[static_method_count]     <== offsets to the info item of the Method Component.
    |   } class_exports[class_count]        <== indexes of this table (list), are considered as tokens, for the associated
    | }                                         export file, when listing the available classes/interfaces of this CAP file.


    ===============> Descriptor.cap/c
    % notes:
        - The Descriptor Component provides sufficient information to parse and verify all elements of the CAP file.
        - Descriptor component in the Extended format contains information about all public and private packages
          contained in the CAP. Public packages in the CAP file must be described first and must be in the same order
          as they are in the Header Component.
        - The "types" element lists the set of field types and method signatures of the fields and methods defined or
        referenced in this CAP file. Those referenced are enumerated in the Constant Pool Component
        - Static final fields of primitive types are not represented as fields in a CAP file, but instead these compile-
          time constants are placed inline in bytecode sequences. The field_count item does not include
          static final field of primitive types defined by this class.

    % structure:
    | descriptor_component_compact {
    |   u1 tag
    |   u2 size
    |   u1 class_count
    |   class_descriptor_info_compact classes[class_count]
    |   type_descriptor_info types
    | }

        | class_descriptor_info_compact {
        |   u1 token                            <= For package-visible class/interface, no token is assigned; hence 0xff
        |   u1 access_flags
        |   class_ref this_class_ref            <= location of class_info structure in the Class component
        |   u1 interface_count                  <= should be 0/zero for interfaces
        |   u2 field_count                      <= should be 0/zero for interfaces
        |   u2 method_count
        |   class_ref interfaces[interface_count]  <= location of class_info structure in the Class component
        |   field_descriptor_info fields[field_count]
        |   method_descriptor_info_compact methods[method_count]    <= For a class, inherited methods are not included in the array.
        | }                                                            For an interface, inherited methods are included in the array.

            | field_descriptor_info {
            |   u1 token                        <= For private or package-visible fields, no token is assigned; hence 0xff
            |   u1 access_flags
            |
            |   union {
            |     static_field_ref static_field     <= As defined in CONSTANT_StaticFieldref_info in constantpool.cap
            |     {
            |       class_ref class
            |       u1 token                        <= Q:what is the difference between this and the "token" we have above?
            |     } instance_field
            |   } field_ref
            |
            |   union {
            |     u2 primitive_type
            |     u2 reference_type                 <= The reference_type item represents a 15-bit offset into the type_descriptor_info
            |   } type                                 structure. The item at the offset must represent the reference type of this field.
            | }

            | method_descriptor_info_compact {
            |   u1 token                            <= If this method is a private or package-visible static method, a private or package-visible
            |   u1 access_flags                        constructor, or a private virtual method it does not have a token assigned. In this case the
            |   u2 method_offset                       value of the token item must be 0xFF.
            |   u2 type_offset
            |   u2 bytecode_count
            |   u2 exception_handler_count
            |   u2 exception_handler_index          <= index to the first exception_handlers table entry in the method component. 0/zero when no exception_handler
            | }

        | type_descriptor_info {
        |   u2 constant_pool_count
        |   u2 constant_pool_types[constant_pool_count]     <= describes the types of the fields and methods referenced in the Constant Pool Component.
        |                                                      For class/interface entries, there is no associated type; hence, the value is 0xffff.
        |                                                      For field or method, the value is an offset into the type_descriptor_info structure.
        |   type_descriptor type_desc[]     <= As defined in class.cap
        | }


    ===============> StaticResources.cap
    % notes:
        - Static Resource Component must be present if any package in this CAP file has any static resources.
        - If none of the packages in this CAP file has any static resources, this component must not be present in this CAP file.
        - contain any static resource that can be represented in a byte format.
        - Size of each static resource must be between 0 and 32767 bytes.
        - The Static Resource Component does not reference any other component.
        -

    % structure:
    | static_resource_component {
    |   u1 tag
    |   u4 size
    |   u2 resource_count       <= Must be > 0
    |   resource_directory_info resource_directory[resource_count]
    |   static_resource_info static_resources[resource_count]
    | }

        | resource_directory_info {
        |   u2 resource_id      <= unique per resource in the CAP file.
        |   u4 resource_size    <= in bytes; must be 0 and 32767 bytes.
        | }

        | static_resource_info {
        |   u1 static_resource[resource_size] <= size comes from respective index in resource_directory
        | }

    """

    def __init__(self):
        self.cap = None
        self.is_extended = False

    @staticmethod
    def get_components(cap_file_path):
        components = {}
        with ZipFile(cap_file_path, "r") as cap_archive:
            for path in cap_archive.namelist():
                filename = path.split("/")[-1]
                if filename.lower().endswith(".cap") or filename.endswith(".capx"):
                    components[filename] = {
                        "raw": cap_archive.read(path),
                        "raw_modified": "",
                    }
        return components

    def _get_header_flags(self, flags):
        FLAG_MAP = {0x01: "INT", 0x02: "EXPORT", 0x04: "APPLET", 0x08: "EXTENDED"}
        return [
            name if flags & bitmask else f"No-{name}"
            for bitmask, name in FLAG_MAP.items()
        ]

    def _parse_version(self, raw_data, major_bytes=1, minor_bytes=1):
        minor_version = b2i(raw_data.read(minor_bytes))
        major_version = b2i(raw_data.read(major_bytes))
        return f"{major_version}.{minor_version}"

    def _parse_package(self, raw_data):
        package = {
            "version-u2": self._parse_version(raw_data),
            "AID_length-u1": b2i(raw_data.read(1)),
        }
        package["AID"] = raw_data.read(package["AID_length-u1"]).hex()
        return package

    def _parse_package_name(self, raw_data):
        name_length = b2i(raw_data.read(1))
        return {
            "name_length-u1": name_length,
            "name": raw_data.read(name_length).decode(),
            "_hint": "length == 0 <=> no remote interface/class",
        }

    def parse_header_component(self):
        component = case_insensitive_get(self.cap, "header.cap")

        if component is None:
            raise KeyError("header.cap was not found in the components!")

        raw_data = BytesIO(component["raw"])
        component["raw"] = component["raw"].hex()

        component["tag-u1"] = b2i(raw_data.read(1))
        component["size-u2"] = b2i(raw_data.read(2))
        component["magic-u4"] = raw_data.read(4).hex()

        component["CAP_Format_version-u2"] = self._parse_version(raw_data)
        self.cap_format = component["CAP_Format_version-u2"]

        component["flags-u1"] = self._get_header_flags(b2i(raw_data.read(1)))
        self.is_extended = "EXTENDED" in component["flags-u1"]

        if self.is_extended:
            component["CAP_version-u2"] = self._parse_version(raw_data)

            cap_aid_length = b2i(raw_data.read(1))
            component["CAP_AID_length-u1"] = cap_aid_length
            component["CAP_AID"] = raw_data.read(cap_aid_length).hex()

            component["packages_count-u1"] = b2i(raw_data.read(1))
            component["packages"] = [
                self._parse_package(raw_data)
                for _ in range(component["packages_count-u1"])
            ]

            component["package_names"] = [
                self._parse_package_name(raw_data)
                for _ in range(component["packages_count-u1"])
            ]
        else:
            component["package"] = self._parse_package(raw_data)

            if self.cap_format >= "2.2":
                component["package_name"] = self._parse_package_name(raw_data)

    def parse_directory_component(self):
        component = case_insensitive_get(self.cap, "directory.cap")

        if component is None:
            raise KeyError("directory.cap was not found in the components!")

        raw_data = BytesIO(component["raw"])
        component["raw"] = component["raw"].hex()

        component["tag-u1"] = b2i(raw_data.read(1))
        component["size-u2"] = b2i(raw_data.read(2))

        format_dependent_length = 4 if self.is_extended else 2
        _sizes = dict()

        _sizes["header-u2"] = b2i(raw_data.read(2))
        _sizes["directory-u2"] = b2i(raw_data.read(2))
        _sizes["applet-u2"] = b2i(raw_data.read(2))
        _sizes["import-u2"] = b2i(raw_data.read(2))
        _sizes["constant_pool-u2"] = b2i(raw_data.read(2))
        _sizes["class-u2"] = b2i(raw_data.read(2))
        _sizes[f"method-u{str(format_dependent_length)}"] = b2i(
            raw_data.read(format_dependent_length)
        )
        _sizes["static_field-u2"] = b2i(raw_data.read(2))
        _sizes[f"reference_location-u{str(format_dependent_length)}"] = b2i(
            raw_data.read(format_dependent_length)
        )
        _sizes["export-u2"] = b2i(raw_data.read(2))
        _sizes[f"descriptor-u{str(format_dependent_length)}"] = b2i(
            raw_data.read(format_dependent_length)
        )

        if self.cap_format >= "2.2":
            _sizes[f"debug-u{str(format_dependent_length)}"] = b2i(
                raw_data.read(format_dependent_length)
            )
        if self.cap_format >= "2.3":
            _sizes["static_resources-u4"] = b2i(raw_data.read(4))

        component["component_sizes"] = _sizes

        # todo: read more about the values and usage of below three fiels
        component["static_field_size-u6"] = {
            "image_size-u2": b2i(raw_data.read(2)),
            "array_init_count-u2": b2i(raw_data.read(2)),
            "array_init_size-u2": b2i(raw_data.read(2)),
        }

        component["import_count-u1"] = b2i(raw_data.read(1))
        component["applet_count-u1"] = b2i(raw_data.read(1))

        if self.is_extended:
            component["method_component_block_count-u1"] = b2i(raw_data.read(1))

        component["custom_count-u1"] = b2i(raw_data.read(1))

        component["custom_components"] = list()
        for _ in range(component["custom_count-u1"]):
            custom_component = {
                "component_tag-u1": b2i(raw_data.read(1)),
                f"size-u{str(format_dependent_length)}": b2i(
                    raw_data.read(format_dependent_length)
                ),
                "AID_length-u1": b2i(raw_data.read(1)),
            }

            custom_component["AID"] = raw_data.read(
                custom_component["AID_length-u1"]
            ).hex()

        # ToDo: check all the other components with the information
        #       provided in this component.

    def parse_applet_component(self):
        component = case_insensitive_get(self.cap, "applet.cap")

        if component is None:
            # ToDo: Log a warning or raise an error if this is required
            return

        raw_data = BytesIO(component["raw"])
        component["raw"] = component["raw"].hex()

        component["tag-u1"] = b2i(raw_data.read(1))
        component["size-u2"] = b2i(raw_data.read(2))

        component["count-u1"] = b2i(raw_data.read(1))

        component["applets"] = list()
        for _ in range(component["count-u1"]):
            aid_len = b2i(raw_data.read(1))
            applet = {
                "AID_length-u1": aid_len,
                "AID": raw_data.read(aid_len).hex(),
            }
            if self.is_extended:
                applet["install_method_component_block_index-u1"] = b2i(
                    raw_data.read(1)
                )
            applet[
                "install_method_offset-u2 (in method_component.info/method_component_block)"
            ] = b2i(raw_data.read(2))

            component["applets"].append(applet)

    def parse_import_component(self):
        component = case_insensitive_get(self.cap, "import.cap")

        if component is None:
            raise KeyError("import.cap was not found in the components!")

        raw_data = BytesIO(component["raw"])
        component["raw"] = component["raw"].hex()

        component["tag-u1"] = b2i(raw_data.read(1))
        component["size-u2"] = b2i(raw_data.read(2))

        component["count-u1"] = b2i(raw_data.read(1))
        component["packages"] = [
            self._parse_package(raw_data) for _ in range(component["count-u1"])
        ]

    def _parse_static_ref(self, raw_data, tag):
        byte_1 = b2i(raw_data.read(1))
        byte_2 = b2i(raw_data.read(1))
        byte_3 = b2i(raw_data.read(1))

        if byte_1 & 0x80 == 0x80:  # external field|method ref
            return {
                "external_ref-u3": {
                    "package_token-u1*": byte_1 & 0x7F,
                    "class_token-u1": byte_2,
                    "token-u1": byte_3,
                }
            }
        else:  # internal field|method ref
            first_element = (
                "method_info_block_index-u1"
                if self.cap_format >= "2.3" and tag == 6  # StaticMethodRef
                else "padding-u1"
            )
            return {
                "internal_ref-u3": {
                    first_element: byte_1,
                    "offset-u2": byte_2 * 256 + byte_3,
                }
            }

    def _parse_class_ref(self, raw_data):
        byte_1 = b2i(raw_data.read(1))
        byte_2 = b2i(raw_data.read(1))

        if byte_1 & 0x80 == 0x80:  # external_class_ref
            return {
                "external_package_token-u1*": byte_1 & 0x7F,
                "external_class_token-u1": byte_2,
            }
        else:  # internal_class_ref
            return {"internal_class_ref-u2": byte_1 * 256 + byte_2}

    def _parse_cp_constant(self, raw_data):
        TAG_MAP = {
            1: "1 (ClassRef)",
            2: "2 (InstanceFieldRef)",
            3: "3 (VirtualMethodRef)",
            4: "4 (SuperMethodRef)",
            5: "5 (StaticFieldRef)",
            6: "6 (StaticMethodRef)",
        }

        tag = b2i(raw_data.read(1))

        constant = {"tag-u1": TAG_MAP.get(tag)}

        match tag:
            case 1 | 2 | 3 | 4:
                constant.update(self._parse_class_ref(raw_data))
                last_element = "padding-u1" if tag == 1 else "token-u1"
                constant.update({last_element: b2i(raw_data.read(1))})
                # todo: probably it's good to add visibility type based on first bit of the token

            case 5 | 6:
                constant.update(self._parse_static_ref(raw_data, tag))

        return constant

    def parse_constantpool_component(self):
        component = case_insensitive_get(self.cap, "constantpool.cap")

        if component is None:
            raise KeyError("constantpool.cap was not found in the components!")

        raw_data = BytesIO(component["raw"])
        component["raw"] = component["raw"].hex()

        component["tag-u1"] = b2i(raw_data.read(1))
        component["size-u2"] = b2i(raw_data.read(2))

        component["count-u2"] = b2i(raw_data.read(2))

        component["constant_pool"] = [
            self._parse_cp_constant(raw_data) for _ in range(component["count-u2"])
        ]

    def _get_class_flags(self, flags):
        FLAG_MAP = {0x2: "REMOTE", 0x4: "SHAREABLE", 0x8: "INTERFACE"}
        return [
            name if flags & bitmask else f"Not-{name}"
            for bitmask, name in FLAG_MAP.items()
        ]

    def _get_parsed_type(self, hex_string):
        HEX_TYPE_MAP = {
            "1": "V",  # Void
            "2": "Z",  # Boolean
            "3": "B",  # Byte
            "4": "S",  # Short
            "5": "I",  # Int
            "6": "L",  # Reference : It is followed by a 2-byte class_ref
            "A": "(Z",  # Boolean Array
            "B": "(B",  # Byte Array
            "C": "(S",  # Short Array
            "D": "(I",  # Int Array
            "E": "(L",  # Reference Array
        }

        parsed_parts = list()
        hex_reader = StringIO(hex_string.upper())

        while hex_char := hex_reader.read(1):

            if hex_char == "0":  # padding for the cases of odd nibble count
                break

            parsed_parts.append(HEX_TYPE_MAP[hex_char])
            if hex_char in ("6", "E"):  # If Reference or Reference Array
                class_ref_hex = hex_reader.read(4)  # 2-byte class_ref = 4 hex chars
                class_ref = self._parse_class_ref(BytesIO(bytes.fromhex(class_ref_hex)))
                parsed_parts.append(f"<{str(class_ref)}>")

        return f"{hex_string}: {''.join(parsed_parts)}"

    def _parse_implemented_interface_info(self, raw_data):
        interface = self._parse_class_ref(raw_data)
        count = b2i(raw_data.read(1))
        index = [b2i(raw_data.read(1)) for _ in range(count)]
        return {"interface-u2": interface, "count-u1": count, "index-u1l": index}

    def _parse_remote_method_info(self, raw_data):
        return {
            "remote_method_hash-u2": raw_data.read(2).hex(),
            "signature_offset-u2": b2i(raw_data.read(2)),
            "virtual_method_token-u1": b2i(raw_data.read(1)),
        }

    def _parse_type_descriptor(self, raw_data):
        _nibble_count = b2i(raw_data.read(1))
        return {
            "nibble_count-u1": _nibble_count,
            "type": self._get_parsed_type(
                raw_data.read(int((_nibble_count + 1) / 2)).hex()
            ),
        }

    def parse_class_component(self):
        component = case_insensitive_get(self.cap, "class.cap")

        if component is None:
            raise KeyError("class.cap was not found in the components!")

        raw_data = BytesIO(component["raw"])
        component["raw"] = component["raw"].hex()

        component["tag-u1"] = b2i(raw_data.read(1))
        component["size-u2"] = b2i(raw_data.read(2))

        if self.cap_format >= "2.2":
            component["signature_pool_length-u2"] = b2i(raw_data.read(2))
            signature_pool_end = raw_data.tell() + component["signature_pool_length-u2"]

            component["signature_pool"] = list()

            while raw_data.tell() < signature_pool_end:
                component["signature_pool"].append(
                    self._parse_type_descriptor(raw_data)
                )

        component["interfaces"] = list()
        component["classes"] = list()

        parse_u1_bitfield = lambda u1_bitfield: {
            "flags-u4b": self._get_class_flags((u1_bitfield >> 4) & 0x0F),
            "interface_count-u4b": u1_bitfield & 0x0F,
        }

        while raw_data.tell() < raw_data.getbuffer().nbytes:

            bitfield = parse_u1_bitfield(b2i(raw_data.read(1)))

            if "INTERFACE" in bitfield["flags-u4b"]:
                component["interfaces"].append(dict())
                interface = component["interfaces"][-1]

                interface["bitfield-u1"] = bitfield

                interface["superinterfaces-u2l"] = [
                    self._parse_class_ref(raw_data)
                    for _ in range(bitfield["interface_count-u4b"])
                ]

                if "ACC_REMOTE" in bitfield["flags-u4b"]:
                    interface_name_length = b2i(raw_data.read(1))
                    interface_name = raw_data.read(interface_name_length).decode()
                    interface["interface_name"] = {
                        "interface_name_length-u1": interface_name_length,
                        "interface_name-u1l": interface_name,
                    }

            else:  # = ClassInfo
                component["classes"].append(dict())
                class_ = component["classes"][-1]

                class_["bitfield-u1"] = bitfield

                class_["super_class_ref-u2"] = self._parse_class_ref(raw_data)

                class_["declared_instance_size-u1"] = b2i(raw_data.read(1))
                class_["first_reference_token-u1"] = b2i(raw_data.read(1))
                class_["reference_count-u1"] = b2i(raw_data.read(1))
                class_["public_method_table_base-u1"] = b2i(raw_data.read(1))
                class_["public_method_table_count-u1"] = b2i(raw_data.read(1))
                class_["package_method_table_base-u1"] = b2i(raw_data.read(1))
                class_["package_method_table_count-u1"] = b2i(raw_data.read(1))

                if self.is_extended:
                    class_["public_virtual_method_table-u2l"] = [
                        {
                            "method_component_block_index-u1": b2i(raw_data.read(1)),
                            "method_offset-u2": b2i(raw_data.read(2)),
                        }
                        for _ in range(class_["public_method_table_count-u1"])
                    ]

                    class_["package_virtual_method_table-u2l"] = [
                        {
                            "method_component_block_index-u1": b2i(raw_data.read(1)),
                            "method_offset-u2": b2i(raw_data.read(2)),
                        }
                        for _ in range(class_["package_method_table_count-u1"])
                    ]

                else:  # compact format
                    class_["public_virtual_method_table-u2l"] = [
                        raw_data.read(2).hex()
                        for _ in range(class_["public_method_table_count-u1"])
                    ]

                    class_["package_virtual_method_table-u2l"] = [
                        raw_data.read(2).hex()
                        for _ in range(class_["package_method_table_count-u1"])
                    ]

                class_["interfaces"] = self._parse_implemented_interface_info(raw_data)

                if self.cap_format >= "2.2" and "ACC_REMOTE" in bitfield["flags-u4b"]:
                    remote_methods_count = b2i(raw_data.read(1))
                    remote_methods = [
                        self._parse_remote_method_info(raw_data)
                        for _ in range(remote_methods_count)
                    ]

                    hash_modifier_length = b2i(raw_data.read(1))
                    hash_modifier = raw_data.read(hash_modifier_length).hex()
                    class_name_length = b2i(raw_data.read(1))
                    class_name = raw_data.read(class_name_length).decode()
                    remote_interfaces_count = b2i(raw_data.read(1))
                    remote_interfaces = [
                        self._parse_class_ref(raw_data)
                        for _ in range(remote_interfaces_count)
                    ]

                    class_["remote_interfaces"] = {
                        "remote_methods_count-u1": remote_methods_count,
                        "remote_methods-u5l": remote_methods,
                        "hash_modifier_length-u1": hash_modifier_length,
                        "hash_modifier-u1l": hash_modifier,
                        "class_name_length-u1": class_name_length,
                        "class_name-u1l": class_name,
                        "remote_interfaces_count-u1": remote_interfaces_count,
                        "remote_interfaces-u2l": remote_interfaces,
                    }

                public_method_count = (
                    class_["public_method_table_base-u1"]
                    + class_["public_method_table_count-u1"]
                )
                class_["public_virtual_method_token_mapping-u1l"] = [
                    b2i(raw_data.read(1)) for _ in range(public_method_count)
                ]

                class_["CAP22_inheritable_public_method_token_count-u1"] = b2i(
                    raw_data.read(1)
                )

    def parse_method_component(self):
        if self.is_extended:
            component = case_insensitive_get(self.cap, "method.capx")

            if component is None:
                raise KeyError("method.capx was not found in the components!")
        else:
            component = case_insensitive_get(self.cap, "method.cap")

            if component is None:
                raise KeyError("method.cap was not found in the components!")

        raw_data = BytesIO(component["raw"])
        component["raw"] = component["raw"].hex()

        component["tag-u1"] = b2i(raw_data.read(1))

        parse_exception_handler_bitfield = lambda u2_bitfield: {
            "stop": (u2_bitfield >> 15) & 1,
            "active_length": u2_bitfield & 0x7FFF,
        }

        if self.is_extended:
            component["size-u4"] = b2i(raw_data.read(4))
            component["method_component_block_count-u1"] = b2i(raw_data.read(1))
            component["method_component_block_offsets-u4"] = [
                b2i(raw_data.read(4))
                for _ in range(component["method_component_block_count-u1"])
            ]
            component["blocks"] = list()
            for idx in range(component["method_component_block_count-u1"]):

                handler_count = b2i(raw_data.read(1))
                exception_handlers = [
                    {
                        "start_offset-u2": b2i(raw_data.read(2)),
                        "bitfield-u2": parse_exception_handler_bitfield(
                            b2i(raw_data.read(2))
                        ),
                        "handler_offset-u2": b2i(raw_data.read(2)),
                        "catch_type_index-u2": b2i(raw_data.read(2)),
                    }
                    for _ in range(handler_count)
                ]

                total_block_length = (
                    component["method_component_block_offsets-u4"][idx + 1]
                    - component["method_component_block_offsets-u4"][idx]
                    if (idx + 1) <= component["method_component_block_count-u1"]
                    else component["size-u4"]
                    - component["method_component_block_offsets-u4"][idx]
                )
                bytes_read_so_far = 1 + 8 * handler_count
                methods = raw_data.read(total_block_length - bytes_read_so_far).hex()

                component["blocks"].append(
                    {
                        "handler_count": handler_count,
                        "exception_handlers": exception_handlers,
                        "methods": methods,
                    }
                )

        else:
            component["size-u2"] = b2i(raw_data.read(2))
            component["handler_count-u1"] = b2i(raw_data.read(1))

            component["exception_handlers"] = [
                {
                    "start_offset-u2": b2i(raw_data.read(2)),
                    "bitfield-u2": parse_exception_handler_bitfield(
                        b2i(raw_data.read(2))
                    ),
                    "handler_offset-u2": b2i(raw_data.read(2)),
                    "catch_type_index-u2": b2i(raw_data.read(2)),
                }
                for _ in range(component["handler_count-u1"])
            ]

            component["methods"] = raw_data.read().hex()
            # ToDo:
            # The byte-code counts of the methods are available in the Descriptor component,
            # which is weird since that component is optional. Another oddity is that the Method
            # component is loaded onto the card before the Descriptor!

    def _get_staticfield_arrayview_type_length(self, type_id):
        TYPE_LENGTH_MAP = {
            2: ("2 (Boolean)", 1),
            3: ("3 (Byte)", 1),
            4: ("4 (Short)", 2),
            5: ("5 (Int)", 4),
        }

        return TYPE_LENGTH_MAP.get(type_id, (f"{type_id} (Unknown Type)", None))

    def _parse_array_init_info(self, raw_data):
        type, type_length = self._get_staticfield_arrayview_type_length(
            b2i(raw_data.read(1))
        )

        # "count" is the number of "bytes", which is not neccessary
        # equal with the number of elements.
        count = b2i(raw_data.read(2))
        number_of_elements = int(count / type_length)

        values = [raw_data.read(type_length).hex() for _ in range(number_of_elements)]

        return {"type-u1": type, "count-u2": count, "values": values}

    def parse_staticfield_component(self):
        component = case_insensitive_get(self.cap, "staticfield.cap")

        if component is None:
            # ToDo: Log a warning or raise an error if this is required
            return

        raw_data = BytesIO(component["raw"])
        component["raw"] = component["raw"].hex()

        component["tag-u1"] = b2i(raw_data.read(1))
        component["size-u2"] = b2i(raw_data.read(2))

        # image_size = reference_count * 2 + default_value_count + non_default_value_count.
        component["image_size-u2"] = b2i(raw_data.read(2))
        component["reference_count-u2"] = b2i(raw_data.read(2))
        component["array_init_count-u2"] = b2i(raw_data.read(2))

        component["array_init"] = [
            self._parse_array_init_info(raw_data)
            for _ in range(component["array_init_count-u2"])
        ]

        component["default_value_count-u2"] = b2i(raw_data.read(2))

        component["non_default_value_count-u2"] = b2i(raw_data.read(2))
        component["non_default_values"] = [
            b2i(raw_data.read(1))
            for _ in range(component["non_default_value_count-u2"])
        ]

    def _parse_reference_location_component_block(self, raw_data):
        byte_index_count = b2i(raw_data.read(2))
        offsets_to_byte_indices = [
            b2i(raw_data.read(1)) for _ in range(byte_index_count)
        ]
        byte2_index_count = b2i(raw_data.read(2))
        offsets_to_byte2_indices = [
            b2i(raw_data.read(1)) for _ in range(byte2_index_count)
        ]

        return {
            "byte_index_count-u2": byte_index_count,
            "offsets_to_byte_indices-u1l": offsets_to_byte_indices,
            "byte2_index_count-u2": byte2_index_count,
            "offsets_to_byte2_indices-u1l": offsets_to_byte2_indices,
        }

    def parse_reflocation_component(self):
        if self.is_extended:
            component = case_insensitive_get(self.cap, "reflocation.capx")

            if component is None:
                raise KeyError("reflocation.capx was not found in the components!")
        else:
            component = case_insensitive_get(self.cap, "reflocation.cap")

            if component is None:
                raise KeyError("reflocation.cap was not found in the components!")

        raw_data = BytesIO(component["raw"])
        component["raw"] = component["raw"].hex()

        component["tag-u1"] = b2i(raw_data.read(1))

        if self.is_extended:
            component["size-u4"] = b2i(raw_data.read(4))
            component["reference_location_component_block_count-u1"] = b2i(
                raw_data.read(1)
            )
            component["blocks"] = [
                self._parse_reference_location_component_block(raw_data)
                for _ in component["reference_location_component_block_count-u1"]
            ]

        else:
            component["size-u2"] = b2i(raw_data.read(2))
            component["byte_index_count-u2"] = b2i(raw_data.read(2))
            component["offsets_to_byte_indices-u1l"] = [
                b2i(raw_data.read(1)) for _ in range(component["byte_index_count-u2"])
            ]
            component["byte2_index_count-u2"] = b2i(raw_data.read(2))
            component["offsets_to_byte2_indices-u1l"] = [
                b2i(raw_data.read(1)) for _ in range(component["byte2_index_count-u2"])
            ]

    def _parse_class_export_info(self, raw_data):
        class_offset = b2i(raw_data.read(2))
        static_field_count = b2i(raw_data.read(1))
        static_method_count = b2i(raw_data.read(1))
        static_field_offsets = [
            b2i(raw_data.read(2)) for _ in range(static_field_count)
        ]

        if self.is_extended:
            last_field_key = "static_methods-u3l"
            last_field_value = [
                {
                    "method_component_block_index-u1": b2i(raw_data.read(1)),
                    "method_offset-u2": b2i(raw_data.read(2)),
                }
                for _ in range(static_method_count)
            ]

        else:
            last_field_key = "static_method_offsets-u2l"
            last_field_value = [
                b2i(raw_data.read(2)) for _ in range(static_method_count)
            ]

        return {
            "class_offset-u1": class_offset,
            "static_field_count-u1": static_field_count,
            "static_method_count-u1": static_method_count,
            "static_field_offsets-u2l": static_field_offsets,
            last_field_key: last_field_value,
        }

    def parse_export_component(self):
        component = case_insensitive_get(self.cap, "export.cap")

        if component is None:
            return

        raw_data = BytesIO(component["raw"])
        component["raw"] = component["raw"].hex()

        component["tag-u1"] = b2i(raw_data.read(1))
        component["size-u2"] = b2i(raw_data.read(2))

        if self.is_extended:
            component["package_count-u1"] = b2i(raw_data.read(1))
            component["package_exports"] = list()

            for _ in range(component["package_count-u1"]):
                class_count = b2i(raw_data.read(1))
                class_exports = [
                    self._parse_class_export_info(raw_data) for _ in range(class_count)
                ]
                component["package_exports"].append(
                    {"class_count-u1": class_count, "class_exports": class_exports}
                )

        else:
            component["class_count-u1"] = b2i(raw_data.read(1))
            component["class_exports"] = [
                self._parse_class_export_info(raw_data)
                for _ in range(component["class_count-u1"])
            ]

    def _parse_type_descriptor_info(self, raw_data):
        constant_pool_count = b2i(raw_data.read(2))
        constant_pool_types = [
            b2i(raw_data.read(2)) for _ in range(constant_pool_count)
        ]
        type_desc = list()
        while raw_data.tell() < len(raw_data.getvalue()):
            type_desc.append(self._parse_type_descriptor(raw_data))
        return {
            "constant_pool_count": constant_pool_count,
            "constant_pool_types": constant_pool_types,
            "type_desc": type_desc,
        }

    def _get_method_descriptor_flags(self, flags):
        FLAG_MAP = {
            0x01: "PUBLIC",
            0x02: "PRIVATE",
            0x04: "PROTECTED",
            0x08: "STATIC",
            0x10: "FINAL",
            0x40: "ABSTRACT",
            0x80: "INIT",  # for constructor
        }
        return [name for bitmask, name in FLAG_MAP.items() if flags & bitmask]

    def _parse_method_descriptor_info(self, raw_data):
        token = b2i(raw_data.read(1))
        access_flags = self._get_method_descriptor_flags(b2i(raw_data.read(1)))

        if self.is_extended:
            method_component_block_index = b2i(
                raw_data.read(1)
            )  # should be 0/zero for interfaces

        method_offset = b2i(raw_data.read(2))  # should be 0/zero for interfaces
        type_offset = b2i(raw_data.read(2))
        bytecode_count = b2i(raw_data.read(2))
        exception_handler_count = b2i(raw_data.read(2))
        exception_handler_index = b2i(raw_data.read(2))

        return {
            "token-u1": token,
            "access_flags-u1": access_flags,
            **(
                {"method_component_block_index-u1": method_component_block_index}
                if self.is_extended
                else {}
            ),
            "method_offset-u2": method_offset,
            "type_offset-u2": type_offset,
            "bytecode_count-u2": bytecode_count,
            "exception_handler_count-u2": exception_handler_count,
            "exception_handler_index-u2": exception_handler_index,
        }

    def _parse_method_descriptor_info_compact(self, raw_data):
        return self._parse_method_descriptor_info(raw_data)

    def _parse_method_descriptor_info_extended(self, raw_data):
        return self._parse_method_descriptor_info(raw_data)

    def _get_primitive_type_data_type(self, value):
        DATA_TYPE_MAP = {
            0x0002: "Boolean",
            0x0003: "Byte",
            0x0004: "Short",
            0x0005: "Int",
        }
        return [
            data_type for bitmask, data_type in DATA_TYPE_MAP.items() if value & bitmask
        ]

    def _get_field_descriptor_flags(self, flags):
        FLAG_MAP = {
            0x01: "PUBLIC",
            0x02: "PRIVATE",
            0x04: "PROTECTED",
            0x08: "STATIC",
            0x10: "FINAL",
        }
        return [name for bitmask, name in FLAG_MAP.items() if flags & bitmask]

    def _parse_field_descriptor_info(self, raw_data):
        token = b2i(raw_data.read(1))
        access_flags = self._get_field_descriptor_flags(b2i(raw_data.read(1)))
        if "STATIC" in access_flags:
            field_ref = {"static_field": self._parse_static_ref(raw_data, tag=5)}
        else:
            field_ref = {
                "instance_field": {
                    "class": self._parse_class_ref(raw_data),
                    "token": b2i(raw_data.read(1)),
                }
            }

        type_bytes = b2i(raw_data.read(2))
        if type_bytes & 0x8000:  # high bit == 1 ==> primitive type
            type = {"primitive_type": self._get_primitive_type_data_type(type_bytes)}
        else:  # reference type
            type = {"reference_type": type_bytes}

        return {
            "token": token,
            "access_flags": access_flags,
            "field_ref": field_ref,
            "type": type,
        }

    def _get_class_descriptor_flags(self, flags):
        FLAG_MAP = {0x01: "PUBLIC", 0x10: "FINAL", 0x40: "INTERFACE", 0x80: "ABSTRACT"}
        return [name for bitmask, name in FLAG_MAP.items() if flags & bitmask]

    def _parse_class_descriptor_info(self, raw_data):
        token = b2i(raw_data.read(1))
        access_flags = self._get_class_descriptor_flags(b2i(raw_data.read(1)))
        this_class_ref = self._parse_class_ref(raw_data)
        interface_count = b2i(raw_data.read(1))
        field_count = b2i(raw_data.read(2))
        method_count = b2i(raw_data.read(2))
        interfaces = [self._parse_class_ref(raw_data) for _ in range(interface_count)]
        fields = [
            self._parse_field_descriptor_info(raw_data) for _ in range(field_count)
        ]
        if self.is_extended:
            methods = [
                self._parse_method_descriptor_info_extended(raw_data)
                for _ in range(method_count)
            ]
        else:
            methods = [
                self._parse_method_descriptor_info_compact(raw_data)
                for _ in range(method_count)
            ]

        return {
            "token-u1": token,
            "access_flags-u1": access_flags,
            "this_class_ref-u2": this_class_ref,
            "interface_count-u1": interface_count,
            "field_count-u2": field_count,
            "method_count-u2": method_count,
            "interfaces": interfaces,
            "fields": fields,
            "methods": methods,
        }

    def _parse_class_descriptor_info_compact(self, raw_data):
        return self._parse_class_descriptor_info(raw_data)

    def _parse_class_descriptor_info_extended(self, raw_data):
        return self._parse_class_descriptor_info(raw_data)

    def parse_descriptor_component(self):
        if self.is_extended:
            component = case_insensitive_get(self.cap, "descriptor.capx")

            if component is None:
                raise KeyError("descriptor.capx was not found in the components!")
        else:
            component = case_insensitive_get(self.cap, "descriptor.cap")

            if component is None:
                raise KeyError("descriptor.cap was not found in the components!")

        raw_data = BytesIO(component["raw"])
        component["raw"] = component["raw"].hex()

        component["tag-u1"] = b2i(raw_data.read(1))

        if self.is_extended:
            component["size-u4"] = b2i(raw_data.read(4))
            component["package_count-u1"] = raw_data.read(1)

            component["packages"] = list()
            for _ in range(component["package_count-u1"]):
                class_count = b2i(raw_data.read(1))
                classes = [
                    self._parse_class_descriptor_info_extended(raw_data)
                    for _ in range(class_count)
                ]
                component["packages"].append(
                    {"class_count-u1": class_count, "classes": classes}
                )

        else:
            component["size-u2"] = b2i(raw_data.read(2))
            component["class_count-u1"] = b2i(raw_data.read(1))
            component["classes"] = [
                self._parse_class_descriptor_info_compact(raw_data)
                for _ in range(component["class_count-u1"])
            ]

        component["types"] = self._parse_type_descriptor_info(raw_data)

    def parse_debug_component(self):
        for key in ["debug.cap", "debug.capx"]:
            component = case_insensitive_get(self.cap, key)
            if component is not None:
                break
        else:
            return  # debug was not found

        raw_data = component["raw"]
        component["raw"] = raw_data.hex()
        # ToDo: Implement!

    def parse_staticresources_component(self):
        if "staticresources.capx" in self.cap:
            component = self.cap["staticresources.capx"]
        else:
            return

        raw_data = BytesIO(component["raw"])
        component["raw"] = component["raw"].hex()

        component["tag-u1"] = b2i(raw_data.read(1))
        component["size-u4"] = b2i(raw_data.read(4))
        component["resource_count-u2"] = b2i(raw_data.read(2))

        component["resource_directory-u6l"] = [
            {
                "resource_id-u2": b2i(raw_data.read(2)),
                "resource_size-u4": b2i(raw_data.read(4)),
            }
            for _ in range(component["resource_count-u2"])
        ]

        component["static_resources"] = [
            raw_data.read(resource["resource_size-u4"]).hex()
            for resource in component["resource_directory-u6l"]
        ]

    def parse(self, cap_file_path):
        self.cap = self.get_components(cap_file_path)

        self.parse_header_component()  #
        self.parse_directory_component()  #
        self.parse_applet_component()  #
        self.parse_import_component()  #
        self.parse_constantpool_component()  #
        self.parse_class_component()  # To Review
        self.parse_method_component()  # ToDo: separation of methods
        self.parse_staticfield_component()  #
        self.parse_reflocation_component()  #
        self.parse_export_component()  #
        self.parse_descriptor_component()  #
        self.parse_debug_component()  # Off-card usage only, so skipped!
        self.parse_staticresources_component()  #

        return json.dumps(self.cap, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description="Read a CAP file and generate corresponding parsed JSON representation."
    )
    parser.add_argument("cap_path", help="Path to the input CAP file")
    parser.add_argument(
        "--output", "-o", help="Optional name/path for the output JSON file"
    )
    parser.add_argument("--print", "-p", action='store_true', help="Print the JSON in the output")

    args = parser.parse_args()

    if not os.path.isfile(args.cap_path):
        print(f"Error: File '{args.cap_path}' does not exist.")
        exit(1)

    if args.output:
        output_file_name = args.output
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        cap_name = ".".join(args.cap_path.split(os.path.sep)[-1].split('.')[:-1])
        output_file_name = f"output{os.path.sep}{timestamp}_{cap_name}_cap.json"

    try:
        cap2json = CAP2JSON()
        json_cap = cap2json.parse(args.cap_path)

        if args.print:
            print(json_cap)
        else:
            with open(output_file_name, "w") as f:
                f.write(json_cap)
                print(f"Parsed CAP file written to '{output_file_name}'")

    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    main()
