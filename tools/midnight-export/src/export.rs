//! midnight-proofs `VerifyingKey` -> `midnight_verifier_core::Vk`.

use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet, HashMap},
};

use ff::{Field, PrimeField};
use group::{Curve, UncompressedEncoding};
use midnight_curves::{Bls12, Fq, G1Projective, G2Affine};
use midnight_proofs::{
    plonk::{Any, Expression, VerifyingKey},
    poly::kzg::KZGCommitmentScheme,
};
use midnight_verifier_core::vk::{
    ColumnKind, ComSlot, EvalSlot, Expr, Lookup, Op, PlanCommitment, PlanSet, Trashcan, Vk,
};

pub type MVk = VerifyingKey<Fq, KZGCommitmentScheme<Bls12>>;

fn g1(p: &G1Projective) -> [u8; 96] {
    let mut a = [0u8; 96];
    a.copy_from_slice(p.to_affine().to_uncompressed().as_ref());
    a
}

pub fn g2(p: &G2Affine) -> [u8; 192] {
    let mut a = [0u8; 192];
    a.copy_from_slice(p.to_uncompressed().as_ref());
    a
}

fn fr(f: &Fq) -> [u8; 32] {
    f.to_repr()
}

fn query_index(qs: &[(usize, i32)], col: usize, rot: i32) -> u32 {
    qs.iter()
        .position(|&(c, r)| c == col && r == rot)
        .expect("query not registered") as u32
}

pub fn export(vk: &MVk, nb_committed: usize, s_g2: &G2Affine, n_g2: &G2Affine) -> Vk {
    let cs = vk.cs();
    let advice_q: Vec<(usize, i32)> = cs
        .advice_queries()
        .iter()
        .map(|(c, r)| (c.index(), r.0))
        .collect();
    let instance_q: Vec<(usize, i32)> = cs
        .instance_queries()
        .iter()
        .map(|(c, r)| (c.index(), r.0))
        .collect();
    let fixed_q: Vec<(usize, i32)> = cs
        .fixed_queries()
        .iter()
        .map(|(c, r)| (c.index(), r.0))
        .collect();

    let constants: RefCell<Vec<[u8; 32]>> = RefCell::new(Vec::new());
    let konst = |f: Fq| -> u32 {
        let b = fr(&f);
        let mut c = constants.borrow_mut();
        if let Some(i) = c.iter().position(|x| *x == b) {
            return i as u32;
        }
        c.push(b);
        (c.len() - 1) as u32
    };
    let conv = |e: &Expression<Fq>| -> Expr {
        Expr(e.evaluate(
            &|s| vec![Op::Const(konst(s))],
            &|_| panic!("virtual selectors are removed during optimization"),
            &|q| {
                vec![Op::Fixed(query_index(
                    &fixed_q,
                    q.column_index(),
                    q.rotation().0,
                ))]
            },
            &|q| {
                vec![Op::Advice(query_index(
                    &advice_q,
                    q.column_index(),
                    q.rotation().0,
                ))]
            },
            &|q| {
                vec![Op::Instance(query_index(
                    &instance_q,
                    q.column_index(),
                    q.rotation().0,
                ))]
            },
            &|c| vec![Op::Challenge(c.index() as u32)],
            &|mut a| {
                a.push(Op::Neg);
                a
            },
            &|mut a, b| {
                a.extend(b);
                a.push(Op::Add);
                a
            },
            &|mut a, b| {
                a.extend(b);
                a.push(Op::Mul);
                a
            },
            &|mut a, s| {
                a.push(Op::Scale(konst(s)));
                a
            },
        ))
    };

    let gates: Vec<Expr> = cs
        .gates()
        .iter()
        .flat_map(|g| g.polynomials().iter().map(&conv))
        .collect();
    let lookups: Vec<Lookup> = cs
        .lookups()
        .iter()
        .map(|l| Lookup {
            inputs: l.input_expressions().iter().map(&conv).collect(),
            tables: l.table_expressions().iter().map(&conv).collect(),
        })
        .collect();
    let trashcans: Vec<Trashcan> = cs
        .trashcans()
        .iter()
        .map(|t| Trashcan {
            selector: conv(t.selector()),
            constraints: t.constraint_expressions().iter().map(&conv).collect(),
        })
        .collect();
    let perm_columns: Vec<(ColumnKind, u32)> = cs
        .permutation()
        .get_columns()
        .iter()
        .map(|c| match c.column_type() {
            Any::Advice(_) => (ColumnKind::Advice, query_index(&advice_q, c.index(), 0)),
            Any::Fixed => (ColumnKind::Fixed, query_index(&fixed_q, c.index(), 0)),
            Any::Instance => (ColumnKind::Instance, query_index(&instance_q, c.index(), 0)),
        })
        .collect();

    let advice_phase = cs.advice_column_phase();
    let num_phases = advice_phase.iter().max().map(|p| p + 1).unwrap_or(1);
    let domain = vk.get_domain();
    let n = vk.n();

    let mut out = Vk {
        k: domain.k(),
        n,
        omega: fr(&domain.get_omega()),
        omega_inv: fr(&domain.get_omega_inv()),
        delta: fr(&<Fq as PrimeField>::DELTA),
        n_inv: fr(&Fq::from(n).invert().unwrap()),
        transcript_repr: fr(&vk.transcript_repr()),
        blinding_factors: cs.blinding_factors() as u32,
        quotient_pieces: domain.get_quotient_poly_degree() as u32,
        cs_degree: cs.degree() as u32,
        advice_phase,
        challenge_phase: cs.challenge_phase(),
        num_phases,
        num_instance_columns: cs.num_instance_columns() as u32,
        nb_committed_instances: nb_committed as u32,
        advice_queries: advice_q.iter().map(|&(c, r)| (c as u32, r)).collect(),
        instance_queries: instance_q.iter().map(|&(c, r)| (c as u32, r)).collect(),
        fixed_queries: fixed_q.iter().map(|&(c, r)| (c as u32, r)).collect(),
        fixed_commitments: vk.fixed_commitments().iter().map(g1).collect(),
        perm_commitments: vk.permutation().commitments().iter().map(g1).collect(),
        perm_columns,
        constants: Vec::new(),
        gates,
        lookups,
        trashcans,
        plan: Vec::new(),
        s_g2: g2(s_g2),
        n_g2: g2(n_g2),
    };
    out.constants = constants.into_inner();
    out.plan = build_plan(&out);
    out
}

/// The verifier's query list, in `verify_algebraic_constraints` order, with
/// commitments named by slot and points by rotation.
fn queries(vk: &Vk) -> Vec<(ComSlot, i32, EvalSlot)> {
    let mut q = Vec::new();
    let nbc = vk.nb_committed_instances;
    let chunks = vk.num_perm_chunks() as u32;
    let last = -(vk.blinding_factors as i32 + 1);
    for (i, &(col, r)) in vk.advice_queries.iter().enumerate() {
        q.push((ComSlot::Advice(col), r, EvalSlot::Advice(i as u32)));
    }
    for (i, &(col, r)) in vk.instance_queries.iter().enumerate() {
        if col < nbc {
            q.push((
                ComSlot::CommittedInstance(col),
                r,
                EvalSlot::Instance(i as u32),
            ));
        }
    }
    for i in 0..chunks {
        q.push((ComSlot::PermProduct(i), 0, EvalSlot::PermProduct(i)));
        q.push((ComSlot::PermProduct(i), 1, EvalSlot::PermNext(i)));
    }
    for i in (0..chunks).rev().skip(1) {
        q.push((ComSlot::PermProduct(i), last, EvalSlot::PermLast(i)));
    }
    for l in 0..vk.lookups.len() as u32 {
        q.push((ComSlot::LookupProduct(l), 0, EvalSlot::LookupProduct(l)));
        q.push((ComSlot::LookupPermInput(l), 0, EvalSlot::LookupInput(l)));
        q.push((ComSlot::LookupPermTable(l), 0, EvalSlot::LookupTable(l)));
        q.push((ComSlot::LookupPermInput(l), -1, EvalSlot::LookupInputInv(l)));
        q.push((ComSlot::LookupProduct(l), 1, EvalSlot::LookupNext(l)));
    }
    for t in 0..vk.trashcans.len() as u32 {
        q.push((ComSlot::Trash(t), 0, EvalSlot::Trash(t)));
    }
    for (i, &(col, r)) in vk.fixed_queries.iter().enumerate() {
        q.push((ComSlot::Fixed(col), r, EvalSlot::Fixed(i as u32)));
    }
    for i in 0..vk.perm_commitments.len() as u32 {
        q.push((ComSlot::PermCommon(i), 0, EvalSlot::PermCommon(i)));
    }
    q.push((ComSlot::Vanishing, 0, EvalSlot::ExpectedH));
    q.push((ComSlot::Random, 0, EvalSlot::Random));
    q
}

/// `construct_intermediate_sets` + the `(len, index)` sort of `multi_prepare`.
pub fn build_plan(vk: &Vk) -> Vec<PlanSet> {
    let qs = queries(vk);
    struct Cd {
        com: ComSlot,
        point_indices: Vec<usize>,
        set_index: usize,
        evals: Vec<Option<EvalSlot>>,
    }
    let mut cmap: Vec<Cd> = Vec::new();
    let mut point_index_map: HashMap<i32, usize> = HashMap::new();
    for &(com, rot, _) in &qs {
        let np = point_index_map.len();
        let pidx = *point_index_map.entry(rot).or_insert(np);
        if let Some(pos) = cmap.iter().position(|c| c.com == com) {
            assert!(!cmap[pos].point_indices.contains(&pidx), "duplicated query");
            cmap[pos].point_indices.push(pidx);
        } else {
            cmap.push(Cd {
                com,
                point_indices: vec![pidx],
                set_index: 0,
                evals: vec![],
            });
        }
    }
    let inv_points: HashMap<usize, i32> = point_index_map.iter().map(|(&r, &i)| (i, r)).collect();
    let mut sets: BTreeMap<BTreeSet<usize>, usize> = BTreeMap::new();
    let mut com_set: Vec<BTreeSet<usize>> = Vec::new();
    for c in &cmap {
        let s: BTreeSet<usize> = c.point_indices.iter().cloned().collect();
        com_set.push(s.clone());
        let ns = sets.len();
        sets.entry(s).or_insert(ns);
    }
    for c in cmap.iter_mut() {
        c.evals = vec![None; c.point_indices.len()];
    }
    for &(com, rot, eval) in &qs {
        let pidx = point_index_map[&rot];
        let ci = cmap.iter().position(|c| c.com == com).unwrap();
        let set = &com_set[ci];
        let set_index = sets[set];
        let pos_in_set = set.iter().position(|&i| i == pidx).unwrap();
        cmap[ci].set_index = set_index;
        cmap[ci].evals[pos_in_set] = Some(eval);
    }
    let mut point_sets: Vec<Vec<i32>> = vec![Vec::new(); sets.len()];
    for (s, &si) in sets.iter() {
        for &p in s {
            point_sets[si].push(inv_points[&p]);
        }
    }
    // Upstream evaluates the chopped commitment at
    // `point_sets[set][point_indices[0]]`, which only works when its point is
    // the first point globally (index 0).
    for c in &cmap {
        if c.com == ComSlot::Vanishing {
            assert_eq!(
                c.point_indices,
                vec![0],
                "vanishing query must be at global point 0"
            );
            assert_eq!(point_sets[c.set_index], vec![0]);
        }
    }
    let mut order: Vec<usize> = (0..point_sets.len()).collect();
    order.sort_by_key(|&i| (point_sets[i].len(), i));
    order
        .iter()
        .map(|&si| PlanSet {
            rotations: point_sets[si].clone(),
            coms: cmap
                .iter()
                .filter(|c| c.set_index == si)
                .map(|c| PlanCommitment {
                    com: c.com,
                    evals: c.evals.iter().map(|e| e.unwrap()).collect(),
                })
                .collect(),
        })
        .collect()
}
