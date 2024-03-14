// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{iter::Sum, ops::Mul};

use curve25519_dalek::scalar::Scalar;
use subtle::{ConditionallySelectable, ConstantTimeEq};

/// Calculate the value at `x_probe`, where values in `controls` correspond to indices 0,1,2...
/// Controls can be scalars or ristretto points.
/// Ristretto point values should correspond to `x*G` where `x` is a scalar value lying on the polynomial,
/// and `G` is the generator point.
pub fn evaluate_lagrange_polynomial<T>(controls: &[T], x_probe: u32) -> T
where
    Scalar: for<'a> Mul<&'a T, Output = T>,
    T: Sum<T>,
{
    let x = Scalar::from(x_probe);
    controls
        .iter()
        .enumerate()
        .map(|(x_j, f_j)| {
            let mut lagrange_coeff = Scalar::ONE;
            let x_j = Scalar::from(x_j as u64);
            for x_m in 0..controls.len() {
                let x_m = Scalar::from(x_m as u64);
                if x_m != x_j {
                    lagrange_coeff *= x - x_m;
                    lagrange_coeff *= (x_j - x_m).invert();
                }
            }
            lagrange_coeff * f_j
        })
        .sum()
}

/// Produce the coefficient of the Lagrange polynomial corresponding to the point x_i,
/// evaluated at 0.
pub fn lagrange_coefficient_at_zero(x_i: Scalar, x_coords: &[Scalar]) -> Scalar {
    let mut denominator = Scalar::ONE;
    let mut numerator = Scalar::ONE;

    for x_j in x_coords.iter() {
        if *x_j != x_i {
            numerator *= x_j;
            denominator *= x_j - x_i;
        }
    }

    numerator * denominator.invert()
}

/// Produce the coefficients of the Lagrange polynomial corresponding to these x
/// coordinates, evaluated at 0. Produces one coefficient for each input.
pub fn lagrange_coefficients_at_zero(x_coords: &[Scalar]) -> impl Iterator<Item = Scalar> {
    // https://en.wikipedia.org/wiki/Lagrange_polynomial
    use std::mem::replace;
    let zero = Scalar::ZERO;
    let one = Scalar::ONE;

    // Compute the numerators. We do this in a fairly roundabout way, in order to avoid doing
    // n^2 multiplications and ever needing to call .invert() (for the numerators)

    // numerator_terms contains just the (0 - x_m) terms in order. These get multiplied
    // together in one big product for each coefficient, except that a single term is left out
    // each time.
    let numerator_terms: Vec<_> = x_coords.iter().map(|xm| -xm).collect();

    // backward_numers is the product of the numerator terms *after* the jth one
    // (exclusive, and in reverse)
    let backward_numers = numerator_terms
        .iter()
        .rev()
        .scan(one, |a, b| Some(replace(a, *a * b)))
        .collect::<Vec<_>>()
        .into_iter()
        .rev();

    // forward_numers is the product of the numerator terms *before* the jth one
    // (exclusive).
    let forward_numers = numerator_terms
        .into_iter()
        .scan(one, |a, b| Some(replace(a, *a * b)));

    // Now we can compute the actual numerators: Each one is the product of the numerator terms
    // before it and the terms after it.
    let numerators = forward_numers.zip(backward_numers).map(|(a, b)| a * b);

    // Uses ct_eq and conditional_select, instead of `if !=`, to make this function
    // constant-time. Also avoids calling invert on zero, which the dalek documentation
    // loudly says is a no-no
    let mut denominators: Vec<_> = x_coords
        .iter()
        .map(|xj| {
            x_coords.iter().map(|xm| xj - xm).fold(one, |acc, diff| {
                acc * Scalar::conditional_select(&diff, &one, diff.ct_eq(&zero))
            })
        })
        .collect();

    Scalar::batch_invert(&mut denominators); // happens in-place

    numerators.into_iter().zip(denominators).map(|(n, d)| n * d)
}
