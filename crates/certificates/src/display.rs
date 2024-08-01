// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fmt::Display;

pub struct MultiItemDisplay<'a, 'b, T: Display> {
    pub items: &'a [T],
    pub indent: usize,
    pub separator: &'b str,
    pub skip_first_indent: bool,
}

impl<'a, 'b, T: Display> Display for MultiItemDisplay<'a, 'b, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (index, item) in self.items.iter().enumerate() {
            if index == 0 && self.skip_first_indent {
                write!(f, "{}", item)?;
            } else {
                write!(f, "{:indent$}{}", "", item, indent = self.indent)?;
            }
            if index < self.items.len() - 1 {
                write!(f, "{}", self.separator)?;
            }
        }
        Ok(())
    }
}

pub struct TruncatedMultiItemDisplay<'a, 'b, T: Display> {
    pub items: &'a [T],
    pub indent: usize,
    pub separator: &'b str,
    pub max_items: usize,
}

impl<'a, 'b, T: Display> Display for TruncatedMultiItemDisplay<'a, 'b, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let total_items = self.items.len();
        let items_to_print = total_items.min(self.max_items);

        write!(
            f,
            "{}",
            MultiItemDisplay {
                items: &self.items[..items_to_print],
                indent: self.indent,
                separator: self.separator,
                skip_first_indent: false,
            }
        )?;

        if total_items > self.max_items {
            write!(
                f,
                "\n{:indent$}({} more)",
                "",
                total_items - self.max_items,
                indent = self.indent
            )?;
        }

        Ok(())
    }
}
