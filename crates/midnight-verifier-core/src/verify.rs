//! Mirrors `midnight_proofs::plonk::verifier::prepare` (0.8.2),
//! `evaluate_identities`, `KZGCommitmentScheme::multi_prepare` (without
//! `truncated-challenges`) and `DualMSM::check`.

use alloc::{vec, vec::Vec};

use crate::{
    transcript::Transcript,
    vk::{ColumnKind, ComSlot, EvalSlot, Expr, Op, Vk},
    Backend, Error, G1_IDENTITY_COMPRESSED,
};

/// Verifies `proof` for the public inputs `pi` (32-byte little-endian
/// scalars) under `vk`. The committed instance is the identity, as in
/// `midnight_zk_stdlib::verify(.., None, ..)`.
pub fn verify<B: Backend>(b: &B, vk: &Vk, pi: &[[u8; 32]], proof: &[u8]) -> Result<(), Error> {
    let nb_committed = vk.nb_committed_instances as usize;
    if vk.num_instance_columns as usize != nb_committed + 1 || vk.cs_degree < 3 {
        return Err(Error::Unsupported);
    }
    let fr = |bytes: &[u8; 32]| b.from_le_canonical(bytes).ok_or(Error::Decode);
    let omega = fr(&vk.omega)?;
    let omega_inv = fr(&vk.omega_inv)?;
    let delta = fr(&vk.delta)?;
    let n_inv = fr(&vk.n_inv)?;
    let constants = vk
        .constants
        .iter()
        .map(&fr)
        .collect::<Result<Vec<_>, _>>()?;

    let mut t = Transcript::new(proof);

    // ---- parse_trace
    t.common(&vk.transcript_repr);
    for _ in 0..nb_committed {
        t.common(&G1_IDENTITY_COMPRESSED);
    }
    let mut len = [0u8; 32];
    len[..8].copy_from_slice(&(pi.len() as u64).to_le_bytes());
    t.common(&len);
    let mut pi_fr = Vec::with_capacity(pi.len());
    for v in pi {
        pi_fr.push(b.from_le_canonical(v).ok_or(Error::InvalidScalar)?);
        t.common(v);
    }

    let num_advice = vk.advice_phase.len();
    let mut advice_coms: Vec<Option<B::G1>> = vec![None; num_advice];
    let mut challenges = vec![b.zero(); vk.challenge_phase.len()];
    for phase in 0..vk.num_phases {
        for (i, &p) in vk.advice_phase.iter().enumerate() {
            if p == phase {
                advice_coms[i] = Some(t.read_point(b)?);
            }
        }
        for (i, &p) in vk.challenge_phase.iter().enumerate() {
            if p == phase {
                challenges[i] = t.squeeze(b);
            }
        }
    }
    let theta = t.squeeze(b);
    let mut lookup_pin = Vec::with_capacity(vk.lookups.len());
    let mut lookup_ptab = Vec::with_capacity(vk.lookups.len());
    for _ in &vk.lookups {
        lookup_pin.push(t.read_point(b)?);
        lookup_ptab.push(t.read_point(b)?);
    }
    let beta = t.squeeze(b);
    let gamma = t.squeeze(b);
    let chunks = vk.num_perm_chunks();
    let mut perm_prod = Vec::with_capacity(chunks);
    for _ in 0..chunks {
        perm_prod.push(t.read_point(b)?);
    }
    let mut lookup_prod = Vec::with_capacity(vk.lookups.len());
    for _ in &vk.lookups {
        lookup_prod.push(t.read_point(b)?);
    }
    let trash_challenge = t.squeeze(b);
    let mut trash_coms = Vec::with_capacity(vk.trashcans.len());
    for _ in &vk.trashcans {
        trash_coms.push(t.read_point(b)?);
    }
    let random_com = t.read_point(b)?;
    let y = t.squeeze(b);

    // ---- verify_algebraic_constraints
    let mut h_coms = Vec::with_capacity(vk.quotient_pieces as usize);
    for _ in 0..vk.quotient_pieces {
        h_coms.push(t.read_point(b)?);
    }
    let x = t.squeeze(b);
    let xn = b.pow(&x, vk.n);

    let rot = |r: i32| -> B::Fr {
        if r >= 0 {
            b.pow(&omega, r as u64)
        } else {
            b.pow(&omega_inv, r.unsigned_abs() as u64)
        }
    };
    // `EvaluationDomain::l_i_range`
    let l_i_range = |from: i32, to_excl: i32| -> Result<Vec<B::Fr>, Error> {
        // omega^r for r in from..to_excl: one pow, then one mul per step
        let mut w: Vec<B::Fr> = Vec::with_capacity((to_excl - from).max(0) as usize);
        let mut cur = rot(from);
        for _ in from..to_excl {
            let next = b.mul(&cur, &omega);
            w.push(cur);
            cur = next;
        }
        let mut d: Vec<B::Fr> = w.iter().map(|wr| b.sub(&x, wr)).collect();
        batch_invert(b, &mut d)?;
        let common = b.mul(&b.sub(&xn, &b.one()), &n_inv);
        Ok(d.iter()
            .zip(w.iter())
            .map(|(di, wr)| b.mul(&b.mul(di, &common), wr))
            .collect())
    };

    let (min_rot, max_rot) = vk
        .instance_queries
        .iter()
        .fold((0i32, 0i32), |(mn, mx), &(_, r)| {
            if r < mn {
                (r, mx)
            } else if r > mx {
                (mn, r)
            } else {
                (mn, mx)
            }
        });
    let l_i_s = l_i_range(-max_rot, pi.len() as i32 + min_rot.abs())?;
    let mut instance_evals = Vec::with_capacity(vk.instance_queries.len());
    for &(col, r) in &vk.instance_queries {
        if (col as usize) < nb_committed {
            instance_evals.push(t.read_scalar(b)?);
        } else {
            let offset = (max_rot - r) as usize;
            let mut acc = b.zero();
            for (j, v) in pi_fr.iter().enumerate() {
                acc = b.add(&acc, &b.mul(v, &l_i_s[offset + j]));
            }
            instance_evals.push(acc);
        }
    }
    let advice_evals = read_n(&mut t, b, vk.advice_queries.len())?;
    let fixed_evals = read_n(&mut t, b, vk.fixed_queries.len())?;
    let random_eval = t.read_scalar(b)?;
    let perm_common = read_n(&mut t, b, vk.perm_commitments.len())?;
    let mut perm_sets = Vec::with_capacity(chunks);
    for i in 0..chunks {
        let p = t.read_scalar(b)?;
        let n = t.read_scalar(b)?;
        let l = if i + 1 < chunks {
            Some(t.read_scalar(b)?)
        } else {
            None
        };
        perm_sets.push((p, n, l));
    }
    let mut lookup_evals = Vec::with_capacity(vk.lookups.len());
    for _ in &vk.lookups {
        let v = read_n(&mut t, b, 5)?;
        lookup_evals.push(v);
    }
    let trash_evals = read_n(&mut t, b, vk.trashcans.len())?;

    // ---- evaluate_identities
    let bf = vk.blinding_factors as i32;
    let l_evals = l_i_range(-(bf + 1), 1)?;
    let l_last = l_evals[0].clone();
    let mut l_blind = b.zero();
    for e in &l_evals[1..(1 + bf as usize)] {
        l_blind = b.add(&l_blind, e);
    }
    let l_0 = l_evals[1 + bf as usize].clone();
    let one = b.one();
    let active = b.sub(&one, &b.add(&l_last, &l_blind));

    let ctx = Ctx {
        constants: &constants,
        fixed: &fixed_evals,
        advice: &advice_evals,
        instance: &instance_evals,
        challenges: &challenges,
    };
    let mut h = b.zero();
    let mut push = |v: B::Fr| h = b.add(&b.mul(&h, &y), &v);

    for g in &vk.gates {
        push(eval_expr(b, g, &ctx)?);
    }
    if let Some(first) = perm_sets.first() {
        push(b.mul(&l_0, &b.sub(&one, &first.0)));
    }
    if let Some(last) = perm_sets.last() {
        push(b.mul(&b.sub(&b.mul(&last.0, &last.0), &last.0), &l_last));
    }
    for i in 1..perm_sets.len() {
        let prev_last = perm_sets[i - 1].2.clone().ok_or(Error::Unsupported)?;
        push(b.mul(&b.sub(&perm_sets[i].0, &prev_last), &l_0));
    }
    let chunk_len = vk.cs_degree as usize - 2;
    for (ci, set) in perm_sets.iter().enumerate() {
        let cols =
            &vk.perm_columns[ci * chunk_len..((ci + 1) * chunk_len).min(vk.perm_columns.len())];
        let pevals = &perm_common[ci * chunk_len..ci * chunk_len + cols.len()];
        let col_eval = |&(kind, q): &(ColumnKind, u32)| -> Result<B::Fr, Error> {
            let src = match kind {
                ColumnKind::Advice => &advice_evals,
                ColumnKind::Fixed => &fixed_evals,
                ColumnKind::Instance => &instance_evals,
            };
            src.get(q as usize).cloned().ok_or(Error::Decode)
        };
        let mut left = set.1.clone();
        for (c, pe) in cols.iter().zip(pevals.iter()) {
            let e = col_eval(c)?;
            left = b.mul(&left, &b.add(&b.add(&e, &b.mul(&beta, pe)), &gamma));
        }
        let mut right = set.0.clone();
        let mut cur_delta = b.mul(&b.mul(&beta, &x), &b.pow(&delta, (ci * chunk_len) as u64));
        for c in cols {
            let e = col_eval(c)?;
            right = b.mul(&right, &b.add(&b.add(&e, &cur_delta), &gamma));
            cur_delta = b.mul(&cur_delta, &delta);
        }
        push(b.mul(&b.sub(&left, &right), &active));
    }
    for (li, l) in vk.lookups.iter().enumerate() {
        let [prod, next, pin, pin_inv, ptab] =
            <[B::Fr; 5]>::try_from(lookup_evals[li].clone()).map_err(|_| Error::Decode)?;
        let compress = |es: &[Expr]| -> Result<B::Fr, Error> {
            let mut acc = b.zero();
            for e in es {
                acc = b.add(&b.mul(&acc, &theta), &eval_expr(b, e, &ctx)?);
            }
            Ok(acc)
        };
        let left = b.mul(&b.mul(&next, &b.add(&pin, &beta)), &b.add(&ptab, &gamma));
        let right = b.mul(
            &b.mul(&prod, &b.add(&compress(&l.inputs)?, &beta)),
            &b.add(&compress(&l.tables)?, &gamma),
        );
        push(b.mul(&l_0, &b.sub(&one, &prod)));
        push(b.mul(&l_last, &b.sub(&b.mul(&prod, &prod), &prod)));
        push(b.mul(&b.sub(&left, &right), &active));
        push(b.mul(&l_0, &b.sub(&pin, &ptab)));
        push(b.mul(&b.mul(&b.sub(&pin, &ptab), &b.sub(&pin, &pin_inv)), &active));
    }
    for (ti, tc) in vk.trashcans.iter().enumerate() {
        let mut acc = b.zero();
        for e in &tc.constraints {
            acc = b.add(&b.mul(&acc, &trash_challenge), &eval_expr(b, e, &ctx)?);
        }
        let q = eval_expr(b, &tc.selector, &ctx)?;
        push(b.sub(&acc, &b.mul(&b.sub(&one, &q), &trash_evals[ti])));
    }
    let vanishing_inv = b.inv(&b.sub(&xn, &one)).ok_or(Error::NotInvertible)?;
    let expected_h = b.mul(&h, &vanishing_inv);

    // ---- multi_prepare
    let x1 = t.squeeze(b);
    let x2 = t.squeeze(b);
    let f_com = t.read_point(b)?;
    let x3 = t.squeeze(b);
    let q_evals_on_x3 = read_n(&mut t, b, vk.plan.len())?;
    let x4 = t.squeeze(b);
    let pi_com = t.read_point(b)?;
    t.assert_empty()?;

    let eval_of = |s: EvalSlot| -> Result<B::Fr, Error> {
        let get = |v: &Vec<B::Fr>, i: u32| v.get(i as usize).cloned().ok_or(Error::Decode);
        match s {
            EvalSlot::Advice(i) => get(&advice_evals, i),
            EvalSlot::Instance(i) => get(&instance_evals, i),
            EvalSlot::Fixed(i) => get(&fixed_evals, i),
            EvalSlot::Random => Ok(random_eval.clone()),
            EvalSlot::PermCommon(i) => get(&perm_common, i),
            EvalSlot::PermProduct(i) => perm_sets
                .get(i as usize)
                .map(|s| s.0.clone())
                .ok_or(Error::Decode),
            EvalSlot::PermNext(i) => perm_sets
                .get(i as usize)
                .map(|s| s.1.clone())
                .ok_or(Error::Decode),
            EvalSlot::PermLast(i) => perm_sets
                .get(i as usize)
                .and_then(|s| s.2.clone())
                .ok_or(Error::Decode),
            EvalSlot::LookupProduct(i) => lookup_evals
                .get(i as usize)
                .map(|v| v[0].clone())
                .ok_or(Error::Decode),
            EvalSlot::LookupNext(i) => lookup_evals
                .get(i as usize)
                .map(|v| v[1].clone())
                .ok_or(Error::Decode),
            EvalSlot::LookupInput(i) => lookup_evals
                .get(i as usize)
                .map(|v| v[2].clone())
                .ok_or(Error::Decode),
            EvalSlot::LookupInputInv(i) => lookup_evals
                .get(i as usize)
                .map(|v| v[3].clone())
                .ok_or(Error::Decode),
            EvalSlot::LookupTable(i) => lookup_evals
                .get(i as usize)
                .map(|v| v[4].clone())
                .ok_or(Error::Decode),
            EvalSlot::Trash(i) => get(&trash_evals, i),
            EvalSlot::ExpectedH => Ok(expected_h.clone()),
        }
    };
    let mut fixed_g1 = Vec::with_capacity(vk.fixed_commitments.len());
    for c in &vk.fixed_commitments {
        fixed_g1.push(b.g1_uncompressed(c).ok_or(Error::Decode)?);
    }
    let mut perm_g1 = Vec::with_capacity(vk.perm_commitments.len());
    for c in &vk.perm_commitments {
        perm_g1.push(b.g1_uncompressed(c).ok_or(Error::Decode)?);
    }

    let mut bases: Vec<B::G1> = Vec::new();
    let mut scalars: Vec<B::Fr> = Vec::new();
    let add_term = |bases: &mut Vec<B::G1>, scalars: &mut Vec<B::Fr>, s: B::Fr, p: &B::G1| {
        if !b.g1_is_identity(p) {
            bases.push(p.clone());
            scalars.push(s);
        }
    };
    let splitting = b.pow(&x, vk.n - 1);

    let mut x4_pow = b.one();
    let mut v = b.zero();
    // f_eval = sum_s x2^s * eval_s, accumulated forwards.
    let mut f_eval = b.zero();
    let mut x2_pow = b.one();
    for (si, set) in vk.plan.iter().enumerate() {
        let points: Vec<B::Fr> = set.rotations.iter().map(|&r| b.mul(&x, &rot(r))).collect();
        let mut q_eval = vec![b.zero(); points.len()];
        let mut x1_pow = b.one();
        for pc in &set.coms {
            if pc.evals.len() != points.len() {
                return Err(Error::Decode);
            }
            for (j, e) in pc.evals.iter().enumerate() {
                q_eval[j] = b.add(&q_eval[j], &b.mul(&eval_of(*e)?, &x1_pow));
            }
            let s = b.mul(&x4_pow, &x1_pow);
            match pc.com {
                ComSlot::Vanishing => {
                    let mut sf = s;
                    for hc in &h_coms {
                        add_term(&mut bases, &mut scalars, sf.clone(), hc);
                        sf = b.mul(&sf, &splitting);
                    }
                }
                ComSlot::CommittedInstance(_) => {}
                other => {
                    let p = match other {
                        ComSlot::Advice(i) => advice_coms.get(i as usize).and_then(|c| c.clone()),
                        ComSlot::Fixed(i) => fixed_g1.get(i as usize).cloned(),
                        ComSlot::PermCommon(i) => perm_g1.get(i as usize).cloned(),
                        ComSlot::PermProduct(i) => perm_prod.get(i as usize).cloned(),
                        ComSlot::LookupPermInput(i) => lookup_pin.get(i as usize).cloned(),
                        ComSlot::LookupPermTable(i) => lookup_ptab.get(i as usize).cloned(),
                        ComSlot::LookupProduct(i) => lookup_prod.get(i as usize).cloned(),
                        ComSlot::Trash(i) => trash_coms.get(i as usize).cloned(),
                        ComSlot::Random => Some(random_com.clone()),
                        _ => None,
                    }
                    .ok_or(Error::Decode)?;
                    add_term(&mut bases, &mut scalars, s, &p);
                }
            }
            x1_pow = b.mul(&x1_pow, &x1);
        }
        // r(x3) by Lagrange's formula, den = prod (x3 - p_j)
        let r_eval = if points.len() == 1 {
            q_eval[0].clone()
        } else {
            let mut dens = Vec::new();
            for (j, pj) in points.iter().enumerate() {
                for (k, pk) in points.iter().enumerate() {
                    if k != j {
                        dens.push(b.sub(pj, pk));
                    }
                }
            }
            batch_invert(b, &mut dens)?;
            let mut acc = b.zero();
            let m = points.len() - 1;
            for (j, qj) in q_eval.iter().enumerate() {
                let mut term = qj.clone();
                let mut di = 0;
                for (k, pk) in points.iter().enumerate() {
                    if k != j {
                        term = b.mul(&term, &b.mul(&b.sub(&x3, pk), &dens[j * m + di]));
                        di += 1;
                    }
                }
                acc = b.add(&acc, &term);
            }
            acc
        };
        let mut den = b.one();
        for p in &points {
            den = b.mul(&den, &b.sub(&x3, p));
        }
        let den_inv = b.inv(&den).ok_or(Error::NotInvertible)?;
        let eval_s = b.mul(&b.sub(&q_evals_on_x3[si], &r_eval), &den_inv);
        f_eval = b.add(&f_eval, &b.mul(&eval_s, &x2_pow));
        x2_pow = b.mul(&x2_pow, &x2);

        v = b.add(&v, &b.mul(&q_evals_on_x3[si], &x4_pow));
        x4_pow = b.mul(&x4_pow, &x4);
    }
    add_term(&mut bases, &mut scalars, x4_pow.clone(), &f_com);
    v = b.add(&v, &b.mul(&f_eval, &x4_pow));
    add_term(&mut bases, &mut scalars, x3, &pi_com);
    let g = b.g1_generator();
    add_term(&mut bases, &mut scalars, b.neg(&v), &g);

    let right = b.msm(&bases, &scalars);
    if b.pairing_check(&pi_com, &vk.s_g2, &right, &vk.n_g2) {
        Ok(())
    } else {
        Err(Error::PairingFailed)
    }
}

struct Ctx<'a, F> {
    constants: &'a [F],
    fixed: &'a [F],
    advice: &'a [F],
    instance: &'a [F],
    challenges: &'a [F],
}

fn eval_expr<B: Backend>(b: &B, e: &Expr, c: &Ctx<'_, B::Fr>) -> Result<B::Fr, Error> {
    let mut st: Vec<B::Fr> = Vec::new();
    let get = |v: &[B::Fr], i: u32| v.get(i as usize).cloned().ok_or(Error::Decode);
    for op in &e.0 {
        match *op {
            Op::Const(i) => st.push(get(c.constants, i)?),
            Op::Fixed(i) => st.push(get(c.fixed, i)?),
            Op::Advice(i) => st.push(get(c.advice, i)?),
            Op::Instance(i) => st.push(get(c.instance, i)?),
            Op::Challenge(i) => st.push(get(c.challenges, i)?),
            Op::Neg => {
                let a = st.pop().ok_or(Error::Decode)?;
                st.push(b.neg(&a));
            }
            Op::Add | Op::Mul => {
                let rhs = st.pop().ok_or(Error::Decode)?;
                let lhs = st.pop().ok_or(Error::Decode)?;
                st.push(if *op == Op::Add {
                    b.add(&lhs, &rhs)
                } else {
                    b.mul(&lhs, &rhs)
                });
            }
            Op::Scale(i) => {
                let a = st.pop().ok_or(Error::Decode)?;
                st.push(b.mul(&a, &get(c.constants, i)?));
            }
        }
    }
    if st.len() != 1 {
        return Err(Error::Decode);
    }
    Ok(st.pop().unwrap())
}

fn read_n<B: Backend>(t: &mut Transcript<'_>, b: &B, n: usize) -> Result<Vec<B::Fr>, Error> {
    (0..n).map(|_| t.read_scalar(b)).collect()
}

/// Montgomery's trick; fails if any element is zero.
fn batch_invert<B: Backend>(b: &B, v: &mut [B::Fr]) -> Result<(), Error> {
    if v.is_empty() {
        return Ok(());
    }
    let mut prefix = Vec::with_capacity(v.len());
    let mut acc = b.one();
    for x in v.iter() {
        prefix.push(acc.clone());
        acc = b.mul(&acc, x);
    }
    let mut inv = b.inv(&acc).ok_or(Error::NotInvertible)?;
    for i in (0..v.len()).rev() {
        let xi = v[i].clone();
        v[i] = b.mul(&inv, &prefix[i]);
        inv = b.mul(&inv, &xi);
    }
    Ok(())
}
