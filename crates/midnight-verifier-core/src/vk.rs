//! Flattened verifying key ("SVK"): everything the verifier needs from a
//! midnight-proofs `VerifyingKey`, plus the opening plan that
//! `construct_intermediate_sets` would build. The plan only depends on the
//! VK structure (commitments are compared by identity, points by rotation),
//! so it is computed once off-chain by `tools/midnight-export`.

use alloc::vec::Vec;

use crate::Error;

pub const SVK_MAGIC: &[u8; 8] = b"DPO2USVK";
pub const SVK_VERSION: u8 = 1;

/// One expression in postfix form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Expr(pub Vec<Op>);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Const(u32),
    Fixed(u32),
    Advice(u32),
    Instance(u32),
    Challenge(u32),
    Neg,
    Add,
    Mul,
    /// Multiply the top of the stack by `constants[i]`.
    Scale(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ColumnKind {
    Advice = 0,
    Fixed = 1,
    Instance = 2,
}

/// A commitment the multi-open argument refers to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComSlot {
    Advice(u32),
    CommittedInstance(u32),
    Fixed(u32),
    PermCommon(u32),
    PermProduct(u32),
    LookupPermInput(u32),
    LookupPermTable(u32),
    LookupProduct(u32),
    Trash(u32),
    /// The quotient pieces, combined with powers of `x^(n-1)`.
    Vanishing,
    Random,
}

/// A claimed evaluation the multi-open argument refers to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvalSlot {
    Advice(u32),
    Instance(u32),
    Fixed(u32),
    Random,
    PermCommon(u32),
    PermProduct(u32),
    PermNext(u32),
    PermLast(u32),
    LookupProduct(u32),
    LookupNext(u32),
    LookupInput(u32),
    LookupInputInv(u32),
    LookupTable(u32),
    Trash(u32),
    ExpectedH,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanCommitment {
    pub com: ComSlot,
    /// One eval per point of the set, in the set's point order.
    pub evals: Vec<EvalSlot>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanSet {
    pub rotations: Vec<i32>,
    pub coms: Vec<PlanCommitment>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lookup {
    pub inputs: Vec<Expr>,
    pub tables: Vec<Expr>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trashcan {
    pub selector: Expr,
    pub constraints: Vec<Expr>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vk {
    pub k: u32,
    pub n: u64,
    pub omega: [u8; 32],
    pub omega_inv: [u8; 32],
    /// `F::DELTA` of the scalar field.
    pub delta: [u8; 32],
    /// `1/n`, the barycentric weight of `omega^0`.
    pub n_inv: [u8; 32],
    pub transcript_repr: [u8; 32],
    pub blinding_factors: u32,
    pub quotient_pieces: u32,
    pub cs_degree: u32,
    pub advice_phase: Vec<u8>,
    pub challenge_phase: Vec<u8>,
    pub num_phases: u8,
    pub num_instance_columns: u32,
    pub nb_committed_instances: u32,
    pub advice_queries: Vec<(u32, i32)>,
    pub instance_queries: Vec<(u32, i32)>,
    pub fixed_queries: Vec<(u32, i32)>,
    pub fixed_commitments: Vec<[u8; 96]>,
    pub perm_commitments: Vec<[u8; 96]>,
    /// Permutation columns: kind and the index of its `Rotation::cur()` query.
    pub perm_columns: Vec<(ColumnKind, u32)>,
    pub constants: Vec<[u8; 32]>,
    pub gates: Vec<Expr>,
    pub lookups: Vec<Lookup>,
    pub trashcans: Vec<Trashcan>,
    pub plan: Vec<PlanSet>,
    /// `[tau]_2` and `-[1]_2`, uncompressed.
    pub s_g2: [u8; 192],
    pub n_g2: [u8; 192],
}

impl Vk {
    pub fn num_perm_chunks(&self) -> usize {
        let chunk = (self.cs_degree as usize).saturating_sub(2).max(1);
        self.perm_columns.len().div_ceil(chunk)
    }
}

// ---------------------------------------------------------------- encoding

struct W(Vec<u8>);

impl W {
    fn u8(&mut self, v: u8) {
        self.0.push(v)
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes())
    }
    fn i32(&mut self, v: i32) {
        self.0.extend_from_slice(&v.to_le_bytes())
    }
    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes())
    }
    fn bytes(&mut self, v: &[u8]) {
        self.0.extend_from_slice(v)
    }
    fn len(&mut self, v: usize) {
        self.u32(v as u32)
    }
    fn expr(&mut self, e: &Expr) {
        self.len(e.0.len());
        for op in &e.0 {
            let (tag, arg) = match *op {
                Op::Const(i) => (0, i),
                Op::Fixed(i) => (1, i),
                Op::Advice(i) => (2, i),
                Op::Instance(i) => (3, i),
                Op::Challenge(i) => (4, i),
                Op::Neg => (5, 0),
                Op::Add => (6, 0),
                Op::Mul => (7, 0),
                Op::Scale(i) => (8, i),
            };
            self.u8(tag);
            if tag <= 4 || tag == 8 {
                self.u32(arg);
            }
        }
    }
    fn exprs(&mut self, es: &[Expr]) {
        self.len(es.len());
        for e in es {
            self.expr(e)
        }
    }
    fn queries(&mut self, q: &[(u32, i32)]) {
        self.len(q.len());
        for &(c, r) in q {
            self.u32(c);
            self.i32(r);
        }
    }
    fn points(&mut self, p: &[[u8; 96]]) {
        self.len(p.len());
        for x in p {
            self.bytes(x)
        }
    }
    fn com(&mut self, c: ComSlot) {
        let (tag, arg) = match c {
            ComSlot::Advice(i) => (0, i),
            ComSlot::CommittedInstance(i) => (1, i),
            ComSlot::Fixed(i) => (2, i),
            ComSlot::PermCommon(i) => (3, i),
            ComSlot::PermProduct(i) => (4, i),
            ComSlot::LookupPermInput(i) => (5, i),
            ComSlot::LookupPermTable(i) => (6, i),
            ComSlot::LookupProduct(i) => (7, i),
            ComSlot::Trash(i) => (8, i),
            ComSlot::Vanishing => (9, 0),
            ComSlot::Random => (10, 0),
        };
        self.u8(tag);
        self.u32(arg);
    }
    fn eval(&mut self, e: EvalSlot) {
        let (tag, arg) = match e {
            EvalSlot::Advice(i) => (0, i),
            EvalSlot::Instance(i) => (1, i),
            EvalSlot::Fixed(i) => (2, i),
            EvalSlot::Random => (3, 0),
            EvalSlot::PermCommon(i) => (4, i),
            EvalSlot::PermProduct(i) => (5, i),
            EvalSlot::PermNext(i) => (6, i),
            EvalSlot::PermLast(i) => (7, i),
            EvalSlot::LookupProduct(i) => (8, i),
            EvalSlot::LookupNext(i) => (9, i),
            EvalSlot::LookupInput(i) => (10, i),
            EvalSlot::LookupInputInv(i) => (11, i),
            EvalSlot::LookupTable(i) => (12, i),
            EvalSlot::Trash(i) => (13, i),
            EvalSlot::ExpectedH => (14, 0),
        };
        self.u8(tag);
        self.u32(arg);
    }
}

struct R<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> R<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.p.checked_add(n).ok_or(Error::Decode)?;
        let s = self.b.get(self.p..end).ok_or(Error::Decode)?;
        self.p = end;
        Ok(s)
    }
    fn arr<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.take(N)?);
        Ok(a)
    }
    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.arr()?))
    }
    fn i32(&mut self) -> Result<i32, Error> {
        Ok(i32::from_le_bytes(self.arr()?))
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.arr()?))
    }
    /// A length, bounded by the remaining input so a hostile blob cannot
    /// make us allocate.
    fn len(&mut self) -> Result<usize, Error> {
        let n = self.u32()? as usize;
        if n > self.b.len() - self.p {
            return Err(Error::Decode);
        }
        Ok(n)
    }
    fn bytes_vec(&mut self) -> Result<Vec<u8>, Error> {
        let n = self.len()?;
        Ok(self.take(n)?.to_vec())
    }
    fn expr(&mut self) -> Result<Expr, Error> {
        let n = self.len()?;
        let mut ops = Vec::with_capacity(n);
        for _ in 0..n {
            let tag = self.u8()?;
            ops.push(match tag {
                0 => Op::Const(self.u32()?),
                1 => Op::Fixed(self.u32()?),
                2 => Op::Advice(self.u32()?),
                3 => Op::Instance(self.u32()?),
                4 => Op::Challenge(self.u32()?),
                5 => Op::Neg,
                6 => Op::Add,
                7 => Op::Mul,
                8 => Op::Scale(self.u32()?),
                _ => return Err(Error::Decode),
            });
        }
        Ok(Expr(ops))
    }
    fn exprs(&mut self) -> Result<Vec<Expr>, Error> {
        let n = self.len()?;
        (0..n).map(|_| self.expr()).collect()
    }
    fn queries(&mut self) -> Result<Vec<(u32, i32)>, Error> {
        let n = self.len()?;
        (0..n).map(|_| Ok((self.u32()?, self.i32()?))).collect()
    }
    fn points(&mut self) -> Result<Vec<[u8; 96]>, Error> {
        let n = self.len()?;
        (0..n).map(|_| self.arr()).collect()
    }
    fn com(&mut self) -> Result<ComSlot, Error> {
        let tag = self.u8()?;
        let i = self.u32()?;
        Ok(match tag {
            0 => ComSlot::Advice(i),
            1 => ComSlot::CommittedInstance(i),
            2 => ComSlot::Fixed(i),
            3 => ComSlot::PermCommon(i),
            4 => ComSlot::PermProduct(i),
            5 => ComSlot::LookupPermInput(i),
            6 => ComSlot::LookupPermTable(i),
            7 => ComSlot::LookupProduct(i),
            8 => ComSlot::Trash(i),
            9 => ComSlot::Vanishing,
            10 => ComSlot::Random,
            _ => return Err(Error::Decode),
        })
    }
    fn eval(&mut self) -> Result<EvalSlot, Error> {
        let tag = self.u8()?;
        let i = self.u32()?;
        Ok(match tag {
            0 => EvalSlot::Advice(i),
            1 => EvalSlot::Instance(i),
            2 => EvalSlot::Fixed(i),
            3 => EvalSlot::Random,
            4 => EvalSlot::PermCommon(i),
            5 => EvalSlot::PermProduct(i),
            6 => EvalSlot::PermNext(i),
            7 => EvalSlot::PermLast(i),
            8 => EvalSlot::LookupProduct(i),
            9 => EvalSlot::LookupNext(i),
            10 => EvalSlot::LookupInput(i),
            11 => EvalSlot::LookupInputInv(i),
            12 => EvalSlot::LookupTable(i),
            13 => EvalSlot::Trash(i),
            14 => EvalSlot::ExpectedH,
            _ => return Err(Error::Decode),
        })
    }
}

impl Vk {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = W(Vec::new());
        w.bytes(SVK_MAGIC);
        w.u8(SVK_VERSION);
        w.u32(self.k);
        w.u64(self.n);
        w.bytes(&self.omega);
        w.bytes(&self.omega_inv);
        w.bytes(&self.delta);
        w.bytes(&self.n_inv);
        w.bytes(&self.transcript_repr);
        w.u32(self.blinding_factors);
        w.u32(self.quotient_pieces);
        w.u32(self.cs_degree);
        w.len(self.advice_phase.len());
        w.bytes(&self.advice_phase);
        w.len(self.challenge_phase.len());
        w.bytes(&self.challenge_phase);
        w.u8(self.num_phases);
        w.u32(self.num_instance_columns);
        w.u32(self.nb_committed_instances);
        w.queries(&self.advice_queries);
        w.queries(&self.instance_queries);
        w.queries(&self.fixed_queries);
        w.points(&self.fixed_commitments);
        w.points(&self.perm_commitments);
        w.len(self.perm_columns.len());
        for &(kind, q) in &self.perm_columns {
            w.u8(kind as u8);
            w.u32(q);
        }
        w.len(self.constants.len());
        for c in &self.constants {
            w.bytes(c);
        }
        w.exprs(&self.gates);
        w.len(self.lookups.len());
        for l in &self.lookups {
            w.exprs(&l.inputs);
            w.exprs(&l.tables);
        }
        w.len(self.trashcans.len());
        for t in &self.trashcans {
            w.expr(&t.selector);
            w.exprs(&t.constraints);
        }
        w.len(self.plan.len());
        for s in &self.plan {
            w.len(s.rotations.len());
            for &r in &s.rotations {
                w.i32(r);
            }
            w.len(s.coms.len());
            for c in &s.coms {
                w.com(c.com);
                w.len(c.evals.len());
                for &e in &c.evals {
                    w.eval(e);
                }
            }
        }
        w.bytes(&self.s_g2);
        w.bytes(&self.n_g2);
        w.0
    }

    pub fn decode(bytes: &[u8]) -> Result<Vk, Error> {
        let mut r = R { b: bytes, p: 0 };
        if r.take(8)? != SVK_MAGIC || r.u8()? != SVK_VERSION {
            return Err(Error::Decode);
        }
        let k = r.u32()?;
        let n = r.u64()?;
        let omega = r.arr()?;
        let omega_inv = r.arr()?;
        let delta = r.arr()?;
        let n_inv = r.arr()?;
        let transcript_repr = r.arr()?;
        let blinding_factors = r.u32()?;
        let quotient_pieces = r.u32()?;
        let cs_degree = r.u32()?;
        let advice_phase = r.bytes_vec()?;
        let challenge_phase = r.bytes_vec()?;
        let num_phases = r.u8()?;
        let num_instance_columns = r.u32()?;
        let nb_committed_instances = r.u32()?;
        let advice_queries = r.queries()?;
        let instance_queries = r.queries()?;
        let fixed_queries = r.queries()?;
        let fixed_commitments = r.points()?;
        let perm_commitments = r.points()?;
        let np = r.len()?;
        let mut perm_columns = Vec::with_capacity(np);
        for _ in 0..np {
            let kind = match r.u8()? {
                0 => ColumnKind::Advice,
                1 => ColumnKind::Fixed,
                2 => ColumnKind::Instance,
                _ => return Err(Error::Decode),
            };
            perm_columns.push((kind, r.u32()?));
        }
        let nc = r.len()?;
        let mut constants = Vec::with_capacity(nc);
        for _ in 0..nc {
            constants.push(r.arr()?);
        }
        let gates = r.exprs()?;
        let nl = r.len()?;
        let mut lookups = Vec::with_capacity(nl);
        for _ in 0..nl {
            let inputs = r.exprs()?;
            let tables = r.exprs()?;
            lookups.push(Lookup { inputs, tables });
        }
        let nt = r.len()?;
        let mut trashcans = Vec::with_capacity(nt);
        for _ in 0..nt {
            let selector = r.expr()?;
            let constraints = r.exprs()?;
            trashcans.push(Trashcan {
                selector,
                constraints,
            });
        }
        let ns = r.len()?;
        let mut plan = Vec::with_capacity(ns);
        for _ in 0..ns {
            let nr = r.len()?;
            let rotations = (0..nr).map(|_| r.i32()).collect::<Result<Vec<_>, _>>()?;
            let ncom = r.len()?;
            let mut coms = Vec::with_capacity(ncom);
            for _ in 0..ncom {
                let com = r.com()?;
                let ne = r.len()?;
                let evals = (0..ne).map(|_| r.eval()).collect::<Result<Vec<_>, _>>()?;
                coms.push(PlanCommitment { com, evals });
            }
            plan.push(PlanSet { rotations, coms });
        }
        let s_g2 = r.arr()?;
        let n_g2 = r.arr()?;
        if r.p != bytes.len() {
            return Err(Error::Decode);
        }
        Ok(Vk {
            k,
            n,
            omega,
            omega_inv,
            delta,
            n_inv,
            transcript_repr,
            blinding_factors,
            quotient_pieces,
            cs_degree,
            advice_phase,
            challenge_phase,
            num_phases,
            num_instance_columns,
            nb_committed_instances,
            advice_queries,
            instance_queries,
            fixed_queries,
            fixed_commitments,
            perm_commitments,
            perm_columns,
            constants,
            gates,
            lookups,
            trashcans,
            plan,
            s_g2,
            n_g2,
        })
    }
}
