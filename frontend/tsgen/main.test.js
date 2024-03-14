/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { test, expect } from "vitest";

const { tsgen } = require("./tsgen");

test("ignores unmarked types", () => {
  expect(
    tsgen(`
      pub struct T1 {
          x: u32,
      }
      pub struct T2 {
          x: u32,
      }
      // tsgen
      pub struct T3 {
          x: u32,
      }
      pub struct T4 {
          x: u32,
      }
    `)
  ).toEqual(["export interface T3 { x: number }"]);
});

test("generates the right types", () => {
  expect(
    tsgen(`
      // tsgen
      pub struct Abc {
          a: u32,
          b: i64,
          c: bool,
          d: String,
          e: Option<bool>,
          f: Option<String>,
          g: Vec<u32>,
          h: (bool, usize),
          i: ComponentVersionGuard<Blah>,
          j: Cow<'static, str>,
      }
    `)
  ).toEqual([
    "export interface Abc { a: number, b: number, c: boolean, d: string, " +
    "e: boolean | null, f: string | null, g: Array<number>, h: [boolean, number], i: string, j: string }",
  ]);
});

test("handles enums", () => {
  expect(
    tsgen(`
      // tsgen
      pub enum E {
          Left,
          Right(u32),
      }
    `)
  ).toEqual([`export type E = "Left" | {Right: number};`]);
});

test("handles renames", () => {
  expect(
    tsgen(`
      // tsgen
      pub enum E {
          #[serde(rename = "goodbye")]
          Hello,
      }
    `)
  ).toEqual([`export type E = "goodbye";`]);
  expect(
    tsgen(`
      // tsgen
      pub struct S {
          #[serde(rename = "new_name")]
          field: String,
      }
    `)
  ).toEqual([`export interface S { new_name: string }`]);
});

test("handles optional fields", () => {
  expect(
    tsgen(`
      // tsgen
      pub struct S {
          #[serde(skip_serializing_if = "Vec::is_empty")]
          x: Vec<String>,
      }
    `)
  ).toEqual([`export interface S { x?: Array<string> }`]);
});

test("handles newtypes", () => {
  expect(
    tsgen(`
      // tsgen
      pub struct S(T);
    `)
  ).toEqual([`export type S = T;`]);
});

test("handles multiple generics", () => {
  expect(
    tsgen(`
      // tsgen
      pub struct S<X, Y> {
          field: T<Y, X>,
      }
    `)
  ).toEqual([`export interface S<X, Y> { field: T<Y, X> }`]);
});

test("handles generic newtypes", () => {
  expect(
    tsgen(`
      // tsgen
      pub struct S<V: Versioned>(T<V>);
    `)
  ).toEqual([`export type S<V> = T<V>;`]);
});

test("handles Self", () => {
  expect(
    tsgen(`
      // tsgen
      pub struct S {
          field: Self,
          other: Option<Self>,
          also: Foo<Self>,
      }
    `)
  ).toEqual([`export interface S { field: S, other: S | null, also: Foo<S> }`]);
});

test("has nice errors", () => {
  expect(() => tsgen(`// tsgen\nfield: u32,`, "/path/to/source.rs")).toThrow(
    /at line 2 in \/path\/to\/source\.rs: Error: field but no name yet/
  );
});

test("handles tsgen =", () => {
  expect(
    tsgen(`
      // tsgen = { x: number }
      struct Special {
        y: bool,
      }
    `)
  ).toEqual(["export type Special = { x: number };"])
});
