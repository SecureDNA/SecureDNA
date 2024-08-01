/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

/**
 * Generate a list of definitions for this source file.
 * @param {string} typeName
 * @param {string} selfName
 * @returns {string}
 */
function translate(typeName, selfName) {
  /** @type RegExpMatchArray | null */
  let m;

  // This type is defined in quickdna, and it's the only type we need from quickdna.
  // It's easier to special-case it than to involve quickdna in the bindings generation.
  if (typeName === "FastaFile<DnaSequence<NucleotideAmbiguous>>") {
    return "{records: {header: string, contents: string, line_range: [number, number]}[]}";
  }
  // This type is given special serialization behavior in `certificates`.
  if ((m = typeName.match(/^ComponentVersionGuard<(.+)>$/))) {
    return "string";
  }

  if ((m = typeName.match(/^Option<(.+)>$/))) {
    return translate(m[1], selfName) + " | null";
  }
  if ((m = typeName.match(/^Result<(.+), (.+)>$/))) {
    const ok = translate(m[1], selfName);
    const err = translate(m[2], selfName);
    return `{Ok: ${ok}} | {Err: ${err}}`;
  }
  if ((m = typeName.match(/^Cow<'.+, (.+)>$/))) {
    return translate(m[1], selfName);
  }
  if ((m = typeName.match(/^Box<(.+)>$/))) {
    return translate(m[1], selfName);
  }
  if ((m = typeName.match(/^\[(.+);/))) {
    return "Array<" + translate(m[1], selfName) + ">";
  }
  if ((m = typeName.match(/^Vec<(.+)>$/))) {
    return "Array<" + translate(m[1], selfName) + ">";
  }
  if ((m = typeName.match(/^(\w+)<(.+)>$/))) {
    return m[1] + "<" + translate(m[2], selfName) + ">";
  }
  if ((m = typeName.match(/^\((.+), (.+)\)$/))) {
    return (
      "[" + translate(m[1], selfName) + ", " + translate(m[2], selfName) + "]"
    );
  }
  switch (typeName) {
    case "Self":
      return selfName;
    case "u8":
    case "u16":
    case "u32":
    case "u64":
    case "usize":
    case "i8":
    case "i16":
    case "i32":
    case "i64":
    case "isize":
    case "f32":
    case "f64":
      return "number";
    case "bool":
      return "boolean";
    case "str":
    case "String":
      return "string";
    default:
      return typeName;
  }
}

/** e.g. `pub struct S(T);` */
const reNewtype =
  /^(?:pub(?:\(crate\))? )?struct ([\w<,>: ]*)\((?:pub(?:\(crate\))? )?(.*)\);/;

/** e.g. `pub type S = T;` */
const reTypeAlias = /^(?:pub(?:\(crate\))? )?type ([\w<,>: ]*) = (.*);/;

/** e.g. `#[serde(rename = "foo")]` */
const reSerdeRename = /^#\[serde.*rename\s*=\s*"(.+)"/;

/** e.g. `#[serde(skip_serializing_if = "foo")]` */
const reSerdeSkip = /^#\[serde.*\bskip_serializing_if\b/;

/** e.g. `#[serde(default = "whatever")]` or `#[serde(default)]` */
const reSerdeDefault = /^#\[serde.*\bdefault\b/;

/** e.g. `#[serde(flatten)]` */
const reSerdeFlatten = /^#\[serde.*\bflatten\b/;

/** e.g. `pub struct {` or `pub enum {` */
const reTypeDefStart = /^(?:pub(?:\(crate\))? )?(struct|enum) ([\w<,> ]*) \{/;

/** e.g. `Foo,` or `Bar,` */
const reEnumItemSimple = /^([A-Z]\w*),/;

/** e.g. `Foo(u32),` or `Bar(Vec<String>),` */
const reEnumItemTagged = /^([A-Z]\w*)\(([\w<,>(): ]+)\),/;

/** e.g. `pub foo: u32,` */
const reStructField = /^(?:pub(?:\(crate\))? )?([\w<,>(): ]*): (.+),$/;

/**
 * Turn `S<T: Trait>` into `S<T>`, mostly
 * @param {string} typeName
 * @returns {string}
 */
function fixTypeName(typeName) {
  return typeName.replace(/(\w+): (\w+)/, (m, t) => t);
}

/**
 * Generate a list of definitions for this source file.
 * @param {string} source
 * @param {string} sourcePath
 * @returns {string[]}
 */
function tsgen(source, sourcePath) {
  /**
   * The current regexp match.
   * @type RegExpMatchArray | null
   */
  let m;

  /**
   * The output: each line is a complete TypeScript type definition.
   * @type string[]
   */
  let output = [];

  /** A flag that means we found "// tsgen" and are now parsing a type. */
  let parsing = false;

  /**
   * The name of the type we're parsing.
   * @type string | null
   */
  let name = null;

  /**
   * The fields or arms of the type we're parsing. These are bits of TypeScript
   * code, eventually joined by ", " (for structs) or " | " (for enums).
   * @type string[]
   */
  let fields = [];

  /**
   * If the user specified // tsgen = type, this holds that type
   * @type string | null
  */
  let manualType = null;

  /** A flag that means we're parsing an enum, rather than a struct. */
  let isEnum = false;

  /**
   * A flag that means we saw a serde "skip_serializing_if" attribute, and so
   * the next field is optional.
   */
  let optional = false;

  /** We saw a "flatten" attribute, so the next field should go to "extends". */
  let flatten = false;

  /**
   * Types this interface extends from.
   * @type string[]
   */
  let bases = [];

  /**
   * After a serde "rename" attribute, this stores the name of the next field.
   * @type string | null
   */
  let rename = null;

  let lineNumber = 0;

  for (let line of source.split("\n")) {
    ++lineNumber;
    try {
      line = line.trim();
      if (parsing) {
        if ((m = line.match(reTypeAlias)) || (m = line.match(reNewtype))) {
          const typeName = fixTypeName(m[1]);
          // This type is given special serialization behavior in `certificates`.
          if (!typeName.match(/^ComponentVersionGuard<(.+)>$/)) {
            output.push(`export type ${typeName} = ${translate(m[2], name)};`);
          }
          parsing = false;
        }
        if ((m = line.match(reSerdeRename))) {
          rename = m[1];
        }
        if ((m = line.match(reSerdeSkip)) || (m = line.match(reSerdeDefault))) {
          optional = true;
        }
        if ((m = line.match(reSerdeFlatten))) {
          flatten = true;
        }
        if ((m = line.match(reTypeDefStart))) {
          if (name) throw new Error("nested type definition");
          isEnum = m[1] === "enum";
          name = m[2];
          if (manualType !== null) {
            output.push(`export type ${name} = ${manualType};`);
            parsing = false;
          }
        } else if (isEnum && (m = line.match(reEnumItemSimple))) {
          if (!name) throw new Error("enum item but no name yet");
          fields.push(`"${rename ?? m[1]}"`);
          rename = undefined;
        } else if (isEnum && (m = line.match(reEnumItemTagged))) {
          if (!name) throw new Error("enum item but no name yet");
          fields.push(`{${rename ?? m[1]}: ${translate(m[2], name)}}`);
          rename = undefined;
        } else if ((m = line.match(reStructField))) {
          if (!name) throw new Error("field but no name yet");
          const typename = translate(m[2], name);

          if (
            line.match(/pub\(crate\) version:/) &&
            sourcePath.match(/certificates/)
          ) {
            // These have a special non-derived Deserialize/Serialize
            // implementation where we just look at the "version" field and
            // ignore everything else. See `impl_encoding_boilerplate` in
            // crates/certificates/src/tokens/token.rs
            parsing = false;
            // Remove any generics
            name = name.replace(/<[^>]*>/, '')
            output.push(`export interface ${name} extends ${typename} {}`);
          } else if (flatten) {
            bases.push(typename);
          } else {
            const question = optional ? "?" : "";
            fields.push(`${rename ?? m[1]}${question}: ${typename}`);
          }
          optional = false;
          flatten = false;
          rename = undefined;
        } else if (line.trim() === "}") {
          if (!name) throw new Error("end of type but no name yet");
          parsing = false;
          if (isEnum) {
            output.push(`export type ${name} = ${fields.join(" | ")};`);
          } else {
            if (bases.length) {
              name += " extends " + bases.join(", ");
            }
            output.push(`export interface ${name} { ${fields.join(", ")} }`);
          }
        }
      } else if (m = line.match(/^\/\/\s*tsgen(?:\s*=\s*(.+))?$/)) {
        parsing = true;
        name = null;
        manualType = m[1]?.trim() ?? null;
        fields = [];
        isEnum = false;
        optional = false;
        flatten = false;
        bases = [];
      }
    } catch (e) {
      throw new Error(`at line ${lineNumber} in ${sourcePath}: ` + e);
    }
  }
  if (parsing) throw new Error(`in ${sourcePath}: unterminated type`);
  return output;
}

module.exports = { tsgen };
