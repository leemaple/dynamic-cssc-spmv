# Route C external-review packet — 2026-08-30

## Scope and evidence boundary

This packet is the external-review revision of the Route C methods and
evidence-boundary paper. It does not contain comparative strategy results.
The sole preregistered qualification run `33261434612` ended
`completed/cancelled` after q2 exceeded the frozen computational deadline; q5
never started, no dispatch capability was minted, and the formal campaign was
not launched. The only retained qualification object was the one-day,
permanently non-evidence q1 handoff recorded in the claim ledger.

The packet is intended to be bound by the annotated Git tag
`route-c-external-review-v1`. The tag, rather than this non-self-referential
file, records the final Git commit.

## Exact packet hashes

| Object | SHA-256 |
|---|---|
| `docs/paper/manuscript-draft.md` | `cbffcbec508dd11c8742ce029fb97f9070a406d9accbb4de06d565cb19b7e450` |
| `docs/paper/manuscript-draft.docx` | `4dc308933d4c698168769a78be31ae8fa2b7240983087ac208a0099d49aab5e0` |
| `docs/paper/paper-idea-detailed-zh.md` | `07e0633f62a96681cabd7d3ba0653a8d91072b6f2662ab2fdd5de654f443a48a` |
| `docs/paper/paper-idea-detailed-zh.docx` | `fa0688ed484cf2d6820a6d4ea46eb5b25a56283c55d6a14b139892c31462afc9` |
| `docs/paper/references.bib` | `601e6d66fb7f99585dcf683129e037db6ae58d0d70c452c8e18f03ce314c80f2` |
| `docs/paper/claim-ledger-draft.md` | `b9253345d9fc1b77ea7345e194aafe917f2103e8f4f09988282837fda1e33dc7` |
| `docs/paper/assets/route-c-protocol-flow.svg` | `d287abd62b92c32a53d24a466dee3debff580b563774395114fb561092b8d09b` |
| `docs/paper/assets/route-c-protocol-flow.png` | `2a07614d949cde27ee272a000598a4d43af1ddf089bfc8c23afa6e22d9f4d4ba` |
| `docs/paper/assets/route-c-evidence-boundary.svg` | `c039966e8c41dbad33fb468683b22812f6bb4321e1ae66c4c426b2dae1dbf8af` |
| `docs/paper/assets/route-c-evidence-boundary.png` | `f997af24c4fc0d818f689618ab6b2e30f701bdb1cd0ecc61eb4bd0a7f289a54f` |
| `docs/research/route-c-manuscript-citation-audit-2026-08-30.md` | `9e3d5b4223e6ebd43cc995f4c542d4acfafe9386387c40c4168db9bc3c1bbf96` |
| `docs/reviews/chatgpt-pro-route-c-manuscript-review-2026-08-30.md` | `8e0146115ce690b3e0b69209fe86007d367d49ecabaef8b99d92992bd10d78d7` |
| `docs/reviews/zcode-glm53-max-route-c-manuscript-review-2026-08-30.md` | `00af2c5d56ddef2ede8e634b0f5e69bf24f7188518faf38fe9d57aae9d1891fd` |
| `scripts/build_route_c_paper_docx.py` | `83958ff55d640035959e04ea30d3a6ae5fd32a33e544bbed5bde1618135a9f29` |

## Independent review disposition

- ZCode GLM-5.3 Max returned `PASS`, with P0 = 0 and P1 = 0. Its six
  non-blocking findings are addressed in this revision.
- ChatGPT Pro returned `AMEND`, with P0 = 0 and P1 = 3. This revision corrects
  the Client A/Client B role diagram, rewrites the unexecuted methodology as a
  frozen counterfactual, and is prepared for a remotely reachable immutable
  tag.
- The primary-source citation audit found P0 = 0, P1 = 3, and four grouped P2
  findings. The Dynamic-CSR and ShieldDB records, citation placement, local
  CSSC audit citation, absence wording, SparseE dated boundary, and final
  publication metadata are corrected here.

## Document verification

- English DOCX: 22 visually inspected pages; 117 editable OMML math elements,
  four tables, two figures, no ZIP/package error, and accessibility audit
  high = 0 / medium = 0. The 26 low findings are raw DOI/URL display text in the
  generated bibliography.
- Chinese technical companion: 24 visually inspected pages using native macOS
  Pages/PDFKit rendering; 295 editable OMML math elements, two figures, no
  ZIP/package error, and accessibility audit high = 0 / medium = 0 / low = 0.
- `git diff --check` and Pandoc citation resolution completed without unresolved
  citation keys.

## Remaining human-owned submission fields

External technical review can use this packet. Submission still requires the
human authors to select a venue and supply verified author order, affiliations,
funding, competing-interest, CRediT, and AI-use statements. A repository
release/archival DOI and venue-specific formatting also remain human-facing
submission work; none is represented as completed here.
