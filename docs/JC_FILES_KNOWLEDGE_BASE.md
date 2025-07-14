- [File Formats](#jc-exp-and-cap-file-formats)
- [CAP File Structure](#cap-file-structure)
    - [Compact vs Extended](#compact-vs-extended)
    - [Inter-Component Dependencies](#inter-component-dependencies)
    - [Detailed CAP Components Strucutres](#detailed-cap-components-structures)
        - [Header](#headercap)
        - [Directory](#directorycap)
        - [Applet](#appletcap)
        - [Import](#importcap)
        - [ConstantPool](#constantpoolcap)
        - [Class](#classcap)
        - [Method](#methodcap)
        - [StaticField](#staticfieldcap)
        - [RefLocation](#reflocationcap)
        - [Export](#exportcap)
        - [Descriptor](#descriptorcap)
        - [StaticResources](#staticresourcescap)
- [Export File Structure](#export-file-structure)


# JC EXP and CAP File Formats
```
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
```

# CAP File Structure

## Compact vs Extended

```
component_compact {
    u1 tag
    u2 size
    u1 info[]
}

component_extended { (since CAP format 2.3)
    u1 tag
    u4 size         <= In some components (ex. Class), only the info[] element differs, while "size" remains u2.
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
```

## Inter-Component Dependencies

```
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
```

## Detailed CAP Components Structures

### **Header.cap**
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

```
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
```

### **Directory.cap**

- When an optional or a conditional component is absent, respective size is set to zero
    + optional/conditional components: applet, export, debug, static_resourses
    + for all the other components, size shall be higher than zero
    + Note that while "Descriptor" component is not an optional component in the cap file,
        loading it into the card during load process is "optional".
- Each custom component has an AID that represents the JC platform name of the component.
    its size has to be in range [5,16], inclusive.

```
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
```

### **Applet.cap**
- If no applets are defined by any of the packages in this CAP file, this component must not
    be present in this CAP file.
- The RID (first 5 bytes) of all of the applet AIDs must have the same value.
- For each applet, install_method_offset item, must be a 16-bit offset into the info item of
    the Method Component (for extended cap: into the method_component_block in the blocks array of Method Component)
- The install(byte[],short,byte) method must be defined in a class that extends the
    javacard.framework.Applet class, directly or indirectly

```
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
```

### **Import.cap**

- Contains an entry for each of the packages referenced in the CAP file
- Does not include the packages defined in this CAP file.
- Components of this CAP file refer to an imported package by using an index
    in this packages table. The index is called a package token.

```
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
```

### **ConstantPool.cap**

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

```
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
```

### **Class.cap**

notes:
- todo

```
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
```

### **Method.cap**

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

```
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
```

### **StaticField.cap**

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
```
        Category       Segment       Content
    ________________|__________|_____________________________________________________
    reference types |    1     | arrays of primitive types initialized by <clinit> methods
    reference types |    2     | initialized to null, including arrays
    primitive types |    3     | initialized to default values
    primitive types |    4     | initialized to non-default values
```
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

```
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
```

### **RefLocation.cap**

- This component contains two lists of offsets for the "info" item of the Method component that
    contain indices of the constant_pool array of ConstantPool component. This includes:
    - all constant pool index operands of instructions
    - all non-zero catch_type_index items of the exception_handlers array
        - The catch_type_index items that have the value of 0 are not included since
            they represent finally blocks instead of particular exception classes.
- Some of the constant pool indices are represented in one-byte values while others are represented
    in two-byte values. Operands of getfield_T and putfield_T instructions are one-byte constant pool
    indices. All other indices in a Method Component are two-byte values.

```
| reference_location_component_compact {
|   u1 tag
|   u2 size                         <= Must be > 0
|   u2 byte_index_count
|   u1 offsets_to_byte_indices[byte_index_count]        <=  1-byte jump offsets into the info item of the Method Component
|   u2 byte2_index_count                                    to each 1-byte constant_pool[] array index.
|   u1 offsets_to_byte2_indices[byte2_index_count]      <=  1-byte jump offsets into the info item of the Method Component
| }                                                         to each 2-byte constant_pool[] array index.
```

### **Export.cap**

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

```
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
```

### **Descriptor.cap**

- The Descriptor Component provides sufficient information to parse and verify all elements of the CAP file.
- Descriptor component in the Extended format contains information about all public and private packages
    contained in the CAP. Public packages in the CAP file must be described first and must be in the same order
    as they are in the Header Component.
- The "types" element lists the set of field types and method signatures of the fields and methods defined or
referenced in this CAP file. Those referenced are enumerated in the Constant Pool Component
- Static final fields of primitive types are not represented as fields in a CAP file, but instead these compile-
    time constants are placed inline in bytecode sequences. The field_count item does not include
    static final field of primitive types defined by this class.

```
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
```

### **StaticResources.cap**

- Static Resource Component must be present if any package in this CAP file has any static resources.
- If none of the packages in this CAP file has any static resources, this component must not be present in this CAP file.
- contain any static resource that can be represented in a byte format.
- Size of each static resource must be between 0 and 32767 bytes.
- The Static Resource Component does not reference any other component.

```
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
```

# Export File Structure
```
ExportFile Structure:
=====================
 ___
| {
| u4  magic
| u1  minor_version
| u1  major_version
|
| u2  constant_pool_count
| cp_info constant_pool[constant_pool_count]        ----> no ordering constraint
|
| u2  this_package                                  ----> A valid index into the constant_pool; must be of type "CONSTANT_Package_info"
|
| u1  referenced_package_count                      ----> (since Export File format 2.3)
| u2  referenced_packages[referenced_package_count] ----> (since Export File format 2.3)
|                                                   ----> Indexes into the constant_pool; must be of type "CONSTANT_Package_info"
|
| u1  export_class_count
| class_info classes[export_class_count]
| }                                     ----> Describes publicly accessible classes/interfaces declared in this package
                                            + In Java Card, following items are externally visible:
                                                1) "public" classes (and interfaces),
                                                2) "public" or "protected" methods,
                                                3) "public" or "protected" fields
                                            Hence, to make on-device reference-resolution possible for the items other
                                            packages have reference to), following six kinds of items in the packages
                                            require external identification (using tokes):
                                                1) classes (and interfaces)
                                                2) static methods
                                                3) virtual methods
                                                4) interface methods
                                                5) static fields
                                                6) instance fields



    Constant Pool Entries:
    ======================

    | cp_info {
    |   u1 tag                              ----> 1: UTF8, 3: Integer, 7: ClassRef, 13: Package
    |   u1 info[]
    | }


        | CONSTANT_Utf8_info {
        |   u1 tag
        |   u2 length
        |   u1 bytes[length]                ----> 0x00 and [0xf0-0xff] are unexpected per JCVM Spec
        | }

        | CONSTANT_Integer_info {
        |   u1 tag
        |   u4 bytes
        | }

        | CONSTANT_Classref_info {          ----> Represents a class or an interface
        |   u1 tag
        |   u2 name_index                   ----> CONSTANT_Utf8_info entry in constant pool
        | }

        | CONSTANT_Package_info {
        |   u1 tag
        |   u1 flags
        |   u2 name_index                   ----> Valid index into the constant_pool; must be of type "CONSTANT_Utf8_info"
        |   u1 minor_version
        |   u1 major_version
        |   u1 aid_length
        |   u1 aid[aid_length]
        | }


    Class Information:
    ==================

    | class_info {
    |   u1 token
    |   u2 access_flags
    |   u2 name_index
    |
    |   u2 export_supers_count
    |   u2 supers[export_supers_count]
    |
    |   u1 export_interfaces_count
    |   u2 interfaces[export_interfaces_count]
    |
    |   u2 export_fields_count
    |   field_info fields[export_fields_count]
    |
    |   u2 export_methods_count
    |   method_info methods[export_methods_count]
    |
    |   u1 CAP22_inheritable_public_method_token_count
    |                                    ----> (since Export File format 2.3)
    | }


        Field Information:
        ==================

        | field_info {
        |   u1 token
        |   u2 access_flags
        |   u2 name_index
        |   u2 descriptor_index
        |   u2 attributes_count
        |   attribute_info attributes[attributes_count]
        | }


            | attribute_info {
            |   u2 attribute_name_index
            |   u4 attribute_length
            |   u1 info[attribute_length]
            | }


        Method Information:
        ===================

        | method_info {
        |   u1 token
        |   u2 access_flags
        |   u2 name_index
        |   u2 descriptor_index
        | }
```

