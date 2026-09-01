# Anonymous IACR CiC current-source submission candidate

This directory is a self-contained anonymous working package for the regular-
paper format of *IACR Communications in Cryptology*. Author names,
affiliations, acknowledgements, repository identities, exact provider run IDs,
and source commit identifiers are deliberately absent from the submission PDF.

The package is a formatting and review artifact. It records both terminal
qualification stops, the narrowly bounded current-source E4 conformance
result, and a distinct admitted 54-cell validation-scaling study. It does not
turn either stopped qualification into performance evidence, broaden the
one-fixture E4 result, rank the maintenance paths, or convert hosted-runner
validation lifecycle time into native/deployment performance.

This 2026-09-01 candidate has passed local build, text, anonymity, citation,
metadata, and full-page visual checks. It remains a local review candidate until
the exact frozen package receives the project's required ChatGPT Pro and ZCode
submission-draft reviews.

## Contents

- `main.tex`: anonymous `iacrcc` submission wrapper;
- `body.tex`: reviewed Route C manuscript body with blind-review tokens;
- `VALIDATION_SCALING_SUPPLEMENT.md`: anonymized full numerical observations,
  exact-rational fits, stopping chronology, and claim-to-evidence boundaries;
- `references.bib`: primary-source-audited bibliography;
- `assets/`: the two manuscript diagrams;
- `iacrcc.cls`: IACR class version 0.78, dated 2025-12-29;
- `lineno.sty`: local LPPL-licensed version 5.9 needed by the bundled class
  when building with the tested Tectonic environment;
- `AI_USE_DISCLOSURE.md`: detailed working disclosure for human and venue
  review. It is not a substitute for author confirmation.

## Reproducible preview build

The tested builder is Tectonic 0.17.0. From this directory:

```sh
mkdir -p build
SOURCE_DATE_EPOCH=1788192000 tectonic main.tex \
  --outdir build --keep-logs --keep-intermediates
```

Two clean builds with that epoch produced byte-identical PDFs. The expected
preview properties are:

- 21 A4 pages;
- bibliography begins on page 19, so the manuscript body occupies pages 1--18
  and remains inside the regular-paper 20-page body limit;
- PDF `Author` metadata is `hidden for submission`;
- no unresolved citations and no overfull boxes;
- expected PDF SHA-256:
  `5a07fb4e4b88831f8b2531d51ece93796f19286f15cd395eab843d5774ef7ade`.

The current Tectonic bundle emits invalid-UTF-8 warnings while reading comments
inside its cached `listofitems.tex`; extracted manuscript text contains no
replacement characters. A few underfull-box warnings remain in narrow table
and bibliography cells and have been visually inspected.

For the publisher build, use the class and build command supplied by the live
CiC submission page. The conditional XeTeX bibliography-anchor workaround in
`main.tex` is inactive under pdfLaTeX and does not change the class's typography
or bibliography style.

## Vendored-file provenance

- Official IACR template archive: `https://publish.iacr.org/iacrcc.zip`
  - archive SHA-256:
    `a37925cca6c62be3804141ee6f7a8faf8d656b3aba30b1f97f26b58b9a92bc3f`
  - `iacrcc.cls` SHA-256:
    `871459a12bc0f41f1efe20b198b296e334af6bbb274d51ad37fa91a484cf5eca`
  - the class declares CC0 dedication terms in its header.
- `lineno.sty` 5.9:
  - upstream: `https://github.com/latex-lineno/lineno`
  - SHA-256:
    `e12f4151f6e86448168fad536850c641c789e8a11babd9d7e8dbe36a38965f37`
  - the file declares LPPL 1.3a-or-later terms in its header.

## Submission boundary

Before an actual upload, a human author must confirm the selected issue and
deadline, author and conflict metadata in the submission portal, the AI-use
disclosure, and the software/data availability route. The anonymous PDF itself
must not be replaced by a repository-identifying or exact-provider-ID version
during double-blind review. The exact-package external-review gate must also be
closed without unresolved P0/P1 findings; that review is a manuscript-quality
gate, not experimental evidence.
