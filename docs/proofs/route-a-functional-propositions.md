# Route A functional propositions: definition-level proofs

Status: S1-candidate proof object. This document proves only the conditional
functional propositions P1--P4 in the frozen Route A preregistration. It is not
a semantic-security proof, a side-channel claim, or evidence that any formal
experiment has run. Its authority begins only when these exact bytes are
included in the clean S1 Behavior Set and the independent source-conformance
record closes.

Throughout, arithmetic is in \(\mathbb Z_t\), where \(t\ge 2\) is the bound
plaintext modulus. Equality of an object means equality of its closed typed
value and, where the admission contract retains bytes, equality of the exact
canonical byte string after a fresh private-boundary rehash.

## P1 — binding soundness

Let the authoritative binding for version \(v\) and query \(q\) be

\[
B^{(v,q)}=(v,s,C,CI,RM,O,P,Q,x,t,M,E,L),
\]

where \(s\) is the logical-state identity; \(C\), \(CI\), and \(RM\) are the
ordered component, global-column-index, and RowMap identities; \(O\) and \(P\)
are the OutputPlan and private-plan identities; \(Q\) and \(x\) are the
prepared-query and query-vector identities; \(M\) is the parameter manifest;
\(E\) is the execution plan; and \(L\) is the ordered retained-payload
inventory. The implementation's closed admission predicate is a conjunction

\[
\operatorname{Accept}(X) = \bigwedge_{j=1}^{n} e_j(X,B^{(v,q)}),
\]

with one necessary equality predicate \(e_j\) for every enumerated field and
retained object. Structural checks first require the exact schema, complete key
set, type, order, multiplicity, and bounds. Byte-bearing predicates then read
the retained object afresh, recompute its SHA-256 digest and byte count, and
compare both to the typed inventory. Consequently, a malformed object cannot
substitute a self-consistent claimed digest: the comparison domain is the
freshly read byte string.

The proof is by exhaustive case analysis over the conjunction.

1. If a structural predicate fails, decoding rejects and no admission value is
   returned.
2. If a typed identity differs, its corresponding \(e_j\) is false, so the
   conjunction is false.
3. If a retained canonical byte string differs, then either its canonical
   decoding fails or its fresh digest/length comparison is false. Deliberate
   SHA-256 collisions are outside the proposition, as frozen in the model.
4. If all predicates are true, the accepted package is equal to
   \(B^{(v,q)}\) in every enumerated typed and byte domain. This is exactly the
   proposition's conclusion; it makes no claim about non-enumerated leakage.

Capability construction is private and lifecycle-owned. Producer capability,
ordinary/strong execution capability, native authorization, independent replay
inspection, and the q2/q4/q5 guards are distinct types. The only branches that
mint or claim the next capability occur after the complete validation function
returns. Exceptions remove private scratch/output or leave the capability
unminted. Provider handoffs are explicitly one-day `NON-EVIDENCE`; q5 and q6
records carry false authority, and the external controller cannot return its
ephemeral dispatch capability until it has independently accepted the complete
terminal chain. Therefore no result capability or formal artifact is reachable
from a strict prefix of the conjunction.

Hence acceptance implies exact equality with \(B^{(v,q)}\) for every frozen
field class and retained canonical object, and every enumerated mismatch rejects
before result-capability or formal-artifact minting. This proves P1 within the
frozen malformed/stale-package model.

## P2 — multi-component reconstruction

For component \(k\), let \(A_k\) be its physical logical-coordinate matrix and
let \(E_k\) embed it into the global logical matrix. Admission requires the
complete decomposition

\[
A=\sum_{k=1}^{K}E_k(A_k)\pmod t.
\]

Let \(z_{k,p}\) denote the decrypted value in physical output lane \(p\) of
component \(k\). The component-execution premise gives

\[
z_{k,p}=\sum_j (A_k)_{p,j}x_j\pmod t.
\]

The validated OutputPlan defines a partial physical-to-logical map \(\pi_k(p)\)
for each emitted share. It rejects duplicate physical slots within a share,
out-of-range physical or logical coordinates, duplicate share identities, and
empty shares. For every logical coordinate \(r\), reconstruction is

\[
\widehat y_r=
\sum_{(k,p):\pi_k(p)=r} z_{k,p}\pmod t,
\]

with the empty sum defined as zero. This one expression covers all three frozen
cases:

- multiple contributors to \(r\) are overlap-summed;
- disjoint horizontal blocks appear at their declared logical coordinates,
  which is concatenation in logical order;
- an unmaterialized logical row has an empty contributor set and receives the
  implicit zero.

Because the plan is total over every emitted physical result and introduces no
unapproved duplicate contributor, regrouping the finite sums gives

\[
\widehat y
=\sum_{k=1}^{K}E_k(A_kx)
=\left(\sum_{k=1}^{K}E_k(A_k)\right)x
=Ax\pmod t.
\]

P3a shows that masks add zero at each overlap coordinate, so inserting and then
cancelling them leaves this derivation unchanged. The argument is independent
of \(K\); therefore P2 holds for any admitted component count.

## P3 — F1-M cancellation and ledger-scoped no-reuse

### P3a: cancellation

For an overlap group \(G_r=(k_1,\ldots,k_g)\), \(g\ge2\), Client A samples
\(m_{r,k_1},\ldots,m_{r,k_{g-1}}\) independently in \(\mathbb Z_t\) and sets

\[
m_{r,k_g}=-\sum_{i=1}^{g-1}m_{r,k_i}\pmod t.
\]

Thus

\[
\sum_{k\in G_r}m_{r,k}
=\sum_{i=1}^{g-1}m_{r,k_i}
-\sum_{i=1}^{g-1}m_{r,k_i}
=0\pmod t.
\]

Each component result at row \(r\) is shifted by its own mask, while Client B's
OutputPlan reconstruction sums all contributors. The reconstructed value is
therefore \(\sum_k z_{k,r}+0\), exactly the unmasked value. Groups of size zero
or one create no random mask. An encrypted-zero dummy is a separate typed class
whose plaintext vector is checked to be exactly zero, so it does not enter the
random-mask argument.

### P3b: state-machine invariant

For a five-field reservation key

\[
R=(q,v,d_O,c,b),
\]

define the durable state machine

\[
\textsf{FREE}\rightarrow\textsf{RESERVED}\rightarrow
\textsf{COMMITTED}(\tau,H)\rightarrow\textsf{CONSUMED}(\tau,H).
\]

`reserve_all` performs one SQLite transaction containing the complete key set.
Uniqueness constraints make the transition all-or-nothing: any pre-existing key
rejects the transaction. The transition occurs before the first randomness call,
so a post-reservation sampling failure does not restore `FREE` and cannot make a
failed identity reusable.

`commit_prepared_f1m` binds a fresh token \(\tau\) to the query, version,
OutputPlan digest, private-plan digest, execution-binding digest, modulus, and
the exact ordered operand commitments \(H\). The database key and foreign-key
closure reject duplicate tokens and orphan commitments. `verify_and_consume`
atomically compares the complete committed batch and changes its consumed bit
from zero to one. A mismatch changes nothing; a successful transition can occur
once because a second transition observes `CONSUMED` and rejects. Independent
replay is read-only and verifies the already consumed rows; it cannot reserve,
sample, commit, or consume.

The evaluation-lane digest contains `unit_attempt_ordinal`, and the query ID and
five-field reservation key derive from that lane. Therefore the sole permitted
provider replacement occupies a different lane and cannot repeat the original
query or reservation identity. This is a ledger-local invariant only: rollback,
cloning, compromise, and cross-device coordination remain excluded. P3 follows.

## P4 — fixed 128-lane segment reconstruction

Fix segment width \(c=128\). Segment \(S_j\) belongs to one logical row
\(r_j\), contains exactly \(c\) lanes, and pads unused suffix lanes with zero.
Let its lane values after multiplication be \(a_{j,0},\ldots,a_{j,c-1}\).
The registered rotate-and-add network is a binary reduction because \(c\) is a
power of two. After stage \(h\), the leader lane contains the sum of the first
\(2^h\) lanes in each aligned block. Induction on \(h=0,\ldots,7\) proves that
after stage seven the predetermined segment-start leader contains

\[
\ell_j=\sum_{p=0}^{127}a_{j,p}\pmod t.
\]

The base case is the original lane. The induction step rotates the adjacent
\(2^h\)-lane subtotal onto the leader and adds it, producing the
\(2^{h+1}\)-lane subtotal. Fixed segment alignment prevents values from another
row-owned segment from entering the leader.

The private OutputPlan maps every leader \(\ell_j\) to its owner row. For a row
with canonical segments \(S_{j_1},\ldots,S_{j_m}\), Client B returns

\[
y_r^{\mathrm{aux}}=\sum_{u=1}^{m}\ell_{j_u}\pmod t.
\]

Induction on \(m\) proves this is the sum of every active auxiliary entry owned
by row \(r\): the empty case is zero; adding segment \(m+1\) adds exactly its
128 lane values. Combining this auxiliary result with the other admitted
components is P2's coordinate sum, hence the final vector equals the direct
plaintext product. The 127/128/129, tombstone, and padding tests exercise the
implementation boundaries; the proof covers every finite \(m\).

## Scope and release condition

These proofs depend on the closed definitions and implementation predicates
mapped in `docs/reviews/route-a-s1-source-conformance.md`. They do not authorize
execution, artifact admission, or manuscript claims by themselves. RA-C1
through RA-C4 remain HOLD unless exact-S1 registration, the registered tests,
independent replay, all guards, and the external terminal controller also pass.
