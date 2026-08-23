# Publication dataset citation and terms record

**Access date for every web source and HTTP observation:** 2026-08-23
(Asia/Shanghai).
**Scope:** the three prespecified real-data sources only: the SNAP Stack
Overflow typed temporal networks, Wikimedia MediaWiki History Simple English
Wikipedia version 2026-07, and NYC TLC 2022 yellow-taxi trip records plus the
taxi-zone lookup.

## Method and interpretation

This record uses only first-party/project-owned pages: Stanford SNAP, Stack
Overflow/Stack Exchange, Wikimedia, and the City of New York. The official HTML
pages and directory listings were inspected, and `HEAD` requests were used to
check the named binary objects. No raw dataset payload was downloaded. The
reported `Content-Length`, `Last-Modified`, and `ETag` values are therefore
transport metadata observed on the access date, not locally verified content
facts.

A separate non-authoritative transport-compatibility probe on 2026-08-23 used
the frozen `curl_cffi==0.16.1` `chrome150` impersonation target, explicit Mac
Chrome 150 user-agent, `Accept-Encoding: identity`, HTTP/2, no redirects, and
`CURLOPT_PROXY` set to the empty string while ambient proxy variables pointed to
an unreachable address. The exact licensing URL returned status 200 at final URL
`https://stackoverflow.com/help/licensing`, no `Content-Encoding` or
`Content-Length`, 142,889 bytes, and local SHA-256
`c3951fa5ad6b3d40c44b5f928dd85fcb9c79538aefe59db69541116198af1ec5`
(2026-08-23T09:47:20.338666Z–09:47:21.974828Z). The exact public-terms URL
returned status 200 at final URL
`https://stackoverflow.com/legal/terms-of-service/public`, likewise no
`Content-Encoding` or `Content-Length`, 179,775 bytes, and local SHA-256
`2388f420efe51045eed6537681c4fd7296ea9280a03aea1dd62357af6496088e`
(2026-08-23T09:47:21.975946Z–09:47:23.193658Z). Numeric HTTP version 3 in
curl_cffi/libcurl denotes HTTP/2. These volatile observations establish only
that the preregistered adapter configuration can retrieve the pages; they are
not an acquisition bundle, license determination, browser-execution claim, or
formal evidence authority.

In this record, **fixed object identity** means the exact object URL or URL set
that the experiment must acquire. It does not mean that a publisher promises
the URL is immutable. None of the three publishers supplies a SHA-256 manifest
for the selected objects on the checked pages. The eventual acquisition record
must therefore add retrieval UTC, final URL, byte count, response metadata, and
a locally computed SHA-256 for every downloaded object.

The local source-set schema implemented during planning is deliberately not an
HTTP acquisition proof. It can rehash local files and check that caller-recorded
URLs, status codes, and media types are members of the frozen schema, but a
caller could attach those fields to bytes obtained elsewhere. Before any result
uses these objects, a repository-owned downloader or CI transaction must fetch
the exact URL, reject an unexpected redirect, record the response metadata, and
bind the downloaded bytes and request/response log into an admitted receipt.

The terms discussion is a conservative publication and artifact boundary, not
legal advice. A statement that use is permitted does not automatically permit
use of a publisher's trademarks, page design, or unrelated site content.

## Bottom line

| Source | Publisher-level identity | Terms result | Publication-safe label |
|---|---|---|---|
| SNAP Stack Overflow | Three named typed objects, but no release tag or publisher checksum | The SNAP dataset page gives provenance and citation, but no object-specific data license. Do not apply the BSD license for SNAP software to these data files. Stack Overflow's current pages describe CC BY-SA terms for the underlying contributions/data dump, with historical versions by contribution date. | “Stanford SNAP Stack Overflow temporal network, using the official `a2q`, `c2q`, and `c2a` objects, accessed 2026-08-23” |
| MediaWiki History Simplewiki | Official version `2026-07`, wiki `simplewiki`, partition `all-time`, one exact Bzip2 TSV object | Wikimedia's MediaWiki History readme explicitly places all Analytics datasets under CC0. | “Wikimedia MediaWiki History Simple English Wikipedia all-time object, version 2026-07” |
| NYC TLC yellow taxi | Twelve year-month Parquet URLs plus one unversioned taxi-zone CSV URL; no release tag or publisher checksum | NYC Open Data states that Open Data has no use restrictions, while requiring attention to general/additional terms, source/version/modification identification, and disclaimers. No CC/ODC license name is stated. | “NYC TLC 2022 monthly yellow-taxi Parquet objects and the official taxi-zone lookup as accessed 2026-08-23” |

## 1. SNAP Stack Overflow typed temporal networks

### Official source register

| Role | Official URL | Page title or object identity | Publisher/site owner | Accessed |
|---|---|---|---|---|
| Dataset record | <https://snap.stanford.edu/data/sx-stackoverflow.html> | HTML title: **SNAP: Network datasets: Stack Overflow temporal network**; page heading: **Stack Overflow temporal network** | Stanford Network Analysis Project (SNAP), Stanford University | 2026-08-23 |
| Typed object `a2q` | <https://snap.stanford.edu/data/sx-stackoverflow-a2q.txt.gz> | Binary object; filename `sx-stackoverflow-a2q.txt.gz` | Stanford SNAP | 2026-08-23 |
| Typed object `c2q` | <https://snap.stanford.edu/data/sx-stackoverflow-c2q.txt.gz> | Binary object; filename `sx-stackoverflow-c2q.txt.gz` | Stanford SNAP | 2026-08-23 |
| Typed object `c2a` | <https://snap.stanford.edu/data/sx-stackoverflow-c2a.txt.gz> | Binary object; filename `sx-stackoverflow-c2a.txt.gz` | Stanford SNAP | 2026-08-23 |
| SNAP citation instruction | <https://snap.stanford.edu/citing.html> | **SNAP: Citing** | Stanford SNAP | 2026-08-23 |
| Contribution-license history | <https://stackoverflow.com/help/licensing> | **What is the license for the content I post? - Help Center - Stack Overflow** | Stack Exchange, Inc. | 2026-08-23 |
| Current public-network terms | <https://stackoverflow.com/legal/terms-of-service/public> | **Public Network Terms of Service - Stack Overflow**; page says “Last updated: November 13, 2025” | Stack Exchange, Inc. | 2026-08-23 |

### Fixed object identity and first-party facts

The SNAP dataset page identifies three interaction types represented by
directed edges `(u, v, t)`:

- `a2q`: user `u` answered user `v`'s question;
- `c2q`: user `u` commented on user `v`'s question; and
- `c2a`: user `u` commented on user `v`'s answer.

It also says that `sx-stackoverflow` is the union of those graphs, that the
graphs were constructed from the Stack Exchange Data Dump, and that node IDs
correspond to the dump's `OwnerUserId`. The three separately linked typed
objects, rather than the untyped union file, are the fixed experimental source
set.

The page reports the following object-level graph statistics:

| Object | Nodes | Temporal edges | Static-graph edges | Time span |
|---|---:|---:|---:|---:|
| `sx-stackoverflow-a2q` | 2,464,606 | 17,823,525 | 16,266,395 | 2,774 days |
| `sx-stackoverflow-c2q` | 1,655,353 | 20,268,151 | 11,226,829 | 2,773 days |
| `sx-stackoverflow-c2a` | 1,646,338 | 25,405,374 | 11,370,342 | 2,773 days |

The direct-object `HEAD` responses resolved with status 200, reported
`Content-Type: application/x-gzip`, and reported:

| Object | Content-Length (bytes) | Last-Modified (UTC) | ETag observed |
|---|---:|---|---|
| `sx-stackoverflow-a2q.txt.gz` | 164,703,302 | 2016-11-29 20:05:57 | `"2aa820b-9d12c46-542761dcdf253"` |
| `sx-stackoverflow-c2q.txt.gz` | 164,264,309 | 2016-11-29 20:06:07 | `"2aa820c-9ca7975-542761e71333c"` |
| `sx-stackoverflow-c2a.txt.gz` | 205,128,052 | 2016-11-29 20:06:17 | `"2aa820d-c3a0174-542761f0a42c6"` |

These filenames and URLs are object identities, not a named SNAP release. The
checked page does not promise immutability and does not publish checksums. The
ETags above are opaque HTTP validators and must not be reported as content
digests.

### Citation recommendation

For a paper, cite both the dataset page and the source paper that the dataset
page itself names. The first entry deliberately omits an author and publication
date because the dataset page supplies neither as bibliographic metadata. The
second entry uses only the authors, title, venue, and year printed by SNAP; no
DOI, page range, or other metadata has been inferred.

```bibtex
@misc{snap_stackoverflow_temporal_network,
  title        = {{Stack Overflow temporal network}},
  howpublished = {Stanford Network Analysis Project},
  url          = {https://snap.stanford.edu/data/sx-stackoverflow.html},
  note         = {Accessed 2026-08-23; experimental source objects:
                  sx-stackoverflow-a2q.txt.gz,
                  sx-stackoverflow-c2q.txt.gz, and
                  sx-stackoverflow-c2a.txt.gz}
}

@inproceedings{paranjape_motifs_in_temporal_networks,
  author    = {Ashwin Paranjape and Austin R. Benson and Jure Leskovec},
  title     = {Motifs in Temporal Networks},
  booktitle = {Proceedings of the Tenth ACM International Conference on Web
               Search and Data Mining},
  year      = {2017},
  note      = {Source citation printed on the SNAP Stack Overflow dataset page}
}
```

SNAP's separate **Citing SNAP** page also supplies a general collection
citation for Jure Leskovec and Andrej Krevl, *SNAP Datasets: Stanford Large
Network Dataset Collection* (June 2014). That citation is publisher-supplied,
but it is less specific than the dataset-page entry above and does not replace
the source-paper citation.

### License and use boundary

- The Stack Overflow dataset page contains no license declaration for these
  three SNAP-hosted objects. The BSD license shown on SNAP software pages is a
  software license and is not evidence that the datasets are BSD-licensed.
- The dataset page says the graphs were constructed from the Stack Exchange
  Data Dump. Stack Overflow's current Public Network Terms say the “Creative
  Commons Data Dump” is licensed under “the CC BY-SA license,” without naming a
  version in that sentence.
- Stack Overflow's current licensing help page supplies the version boundary
  for publicly accessible user contributions: before 2011-04-08 UTC, CC BY-SA
  2.5; from 2011-04-08 through 2018-05-01 UTC, CC BY-SA 3.0; on or after
  2018-05-02 UTC, CC BY-SA 4.0. It says the applicable license for each question
  and answer revision appears on the post timeline.
- Those pages do not expressly classify SNAP's derived edge triples, or grant a
  new single license for SNAP's repackaged typed files. Therefore do not label
  the three files “CC BY-SA 4.0,” “BSD,” “public domain,” or “unrestricted.”
  Retain SNAP and Stack Exchange provenance, cite the dataset and source paper,
  and prefer reproducibility-by-downloader plus hashes over redistributing the
  raw SNAP files. Raw redistribution needs a separate terms review.

### Manuscript claim boundary

Safe, when cited to the SNAP dataset page:

- SNAP publishes a directed temporal Stack Overflow interaction network and
  separately links the official `a2q`, `c2q`, and `c2a` files.
- The three roles have the meanings listed above, use `SRC DST UNIXTS`, and were
  constructed from the Stack Exchange Data Dump.
- The page-reported node, temporal-edge, static-edge, and time-span statistics
  in the table above.
- “We formed a deterministic, type-preserving union of the three official
  typed objects” is safe as a statement of this study's transform. Do not imply
  that SNAP's untyped union file retains a per-edge type field.

Do not state without additional evidence:

- that SNAP issued an immutable or versioned release of these objects;
- that SNAP published a checksum for them;
- that the typed objects have one blanket BSD, CC BY-SA 4.0, or public-domain
  license; or
- that raw-file redistribution is permission-free.

## 2. Wikimedia MediaWiki History: Simplewiki 2026-07

### Official source register

| Role | Official URL | Page title or object identity | Publisher/site owner | Accessed |
|---|---|---|---|---|
| Dataset record and license statement | <https://dumps.wikimedia.org/other/mediawiki_history/readme.html> | HTML title: **Analytics: MediaWiki History**; page heading: **Analytics Datasets: MediaWiki History** | Wikimedia Foundation, Analytics/Data Platform | 2026-08-23 |
| Release directory | <https://dumps.wikimedia.org/other/mediawiki_history/2026-07/simplewiki/> | **Index of /other/mediawiki_history/2026-07/simplewiki/** | Wikimedia Foundation Dumps | 2026-08-23 |
| Fixed object | <https://dumps.wikimedia.org/other/mediawiki_history/2026-07/simplewiki/2026-07.simplewiki.all-time.tsv.bz2> | Binary object; filename `2026-07.simplewiki.all-time.tsv.bz2` | Wikimedia Foundation Dumps | 2026-08-23 |
| Schema and semantics | <https://wikitech.wikimedia.org/wiki/Data_Platform/Data_Lake/Edits/MediaWiki_history_dumps> | **Data Platform/Data Lake/Edits/MediaWiki history dumps - Wikitech** | Wikimedia Foundation Data Platform | 2026-08-23 |
| CC0 legal instrument linked by the readme | <https://creativecommons.org/publicdomain/zero/1.0/> | **CC0 1.0 Universal** | Creative Commons | 2026-08-23 |

### Fixed release/object identity and first-party facts

The fixed identity is:

```text
dataset family: MediaWiki History
version:        2026-07
wiki database:  simplewiki
partition:      all-time
object:         2026-07.simplewiki.all-time.tsv.bz2
```

The official directory listed that one object as 985,335,238 bytes with a
directory timestamp of 2026-08-07 11:02. Its direct `HEAD` response resolved
with status 200 and reported `Content-Type: application/octet-stream`,
`Content-Length: 985335238`, `Last-Modified: Fri, 07 Aug 2026 11:02:55 GMT`,
and `ETag: "6a75bb5f-3abb05c6"`.

The readme says that MediaWiki History is a denormalized historical record of
revision, user, and page events since 2001; updates are monthly; each version is
named for the last featured month in `YYYY-MM` form; and each update is a full
dump rather than an incremental download. It defines object paths as
`/<version>/<wiki>/<version>.<wiki>.<time-range>.tsv.bz2`. The Wikitech page
further states that revision history is supplied **without article text**.

This is the strongest publisher-level release identity among the three sources,
but it is not a permanence guarantee. The readme says only the last two
versions are retained. It also explains that later renames, moves, reverts, or
logging-table changes can cause a newer full snapshot to reconstruct old events
differently. The ETag is not a publisher checksum; preserve a local SHA-256
after acquisition.

### Citation recommendation

The checked official pages do not provide a dataset-specific author/date
citation. This conservative entry therefore uses the official page title and
puts the exact release/object identity in `note`, without inventing author,
publication year, or page numbers.

```bibtex
@misc{wikimedia_mediawiki_history_simplewiki_2026_07,
  title        = {{Analytics Datasets: MediaWiki History}},
  howpublished = {Wikimedia Analytics data dump},
  url          = {https://dumps.wikimedia.org/other/mediawiki_history/readme.html},
  note         = {Version 2026-07, simplewiki all-time object
                  2026-07.simplewiki.all-time.tsv.bz2;
                  accessed 2026-08-23}
}
```

### License and use boundary

- The official MediaWiki History readme states that **all Analytics datasets
  are available under the Creative Commons CC0 dedication** and links CC0 1.0
  Universal. That statement directly covers this Analytics dataset.
- CC0 does not impose an attribution condition, but citing Wikimedia and
  recording the exact release/object is still required for scholarly
  provenance and reproducibility.
- The CC0 statement covers the Analytics dataset. It should not be generalized
  to Wikimedia trademarks, the Wikitech documentation page (whose footer says
  its text is CC BY-SA), or Wikipedia article text. The Wikitech dataset page
  expressly says that article text is not present in MediaWiki History.

### Manuscript claim boundary

Safe, when cited to the readme, directory, and schema page as appropriate:

- MediaWiki History is a monthly, denormalized history of Wikimedia revision,
  user, and page events since 2001, and revision records do not include article
  text.
- The experiment uses the Simple English Wikipedia `simplewiki` all-time
  object in official version `2026-07`, with the exact filename and observed
  byte count above.
- Wikimedia makes Analytics datasets available under CC0.
- A revision-create record can be described as an edit event; the Wikitech
  schema explicitly maps `event_entity = revision` and `event_type = create` to
  “Editing a page.”

Do not state:

- that the URL is permanently retained or that the object is publisher-certified
  immutable;
- that Wikimedia supplied a SHA-256 checksum;
- that successive monthly snapshots reconstruct all historical rows
  identically; or
- that Wikipedia article text or all linked Wikimedia material is covered by
  this dataset's CC0 statement.

## 3. NYC TLC 2022 yellow-taxi records and taxi zones

### Official source register

| Role | Official URL | Page title or object identity | Publisher/site owner | Accessed |
|---|---|---|---|---|
| Dataset landing page and object links | <https://www.nyc.gov/site/tlc/about/tlc-trip-record-data.page> | **TLC Trip Record Data - TLC**; page heading: **TLC Trip Record Data** | New York City Taxi and Limousine Commission | 2026-08-23 |
| Yellow-taxi field documentation | <https://www.nyc.gov/assets/tlc/downloads/pdf/data_dictionary_trip_records_yellow.pdf> | **Data Dictionary – Yellow Taxi Trip Records** | New York City Taxi and Limousine Commission | 2026-08-23 |
| Open-data reuse summary | <https://opendata.cityofnewyork.us/faq/> | **NYC Open Data - FAQ** | City of New York, NYC Open Data | 2026-08-23 |
| Current open-data terms | <https://opendata.cityofnewyork.us/overview/#termsofuse> | **NYC Open Data - Overview**, section **Open Data Terms of Use** | City of New York, NYC Office of Technology and Innovation | 2026-08-23 |
| Public policy details | <https://cityofnewyork.github.io/opendatatsm/publicpolicies.html> | HTML title: **NYC Open Data Technical Standards Manual**; page heading: **Public Policies** | City of New York | 2026-08-23 |
| General site terms | <https://www.nyc.gov/main/terms-of-use> | **Terms of Use - nyc.gov** | City of New York | 2026-08-23 |

For the Open Data Overview row, the HTTP fetch identity is the no-fragment URL
`https://opendata.cityofnewyork.us/overview/`; `termsofuse` is stored separately
as the reviewed section anchor because a URL fragment is not sent in the HTTP
request. Each retained terms object must record its own retrieval UTC, final
URL, status, normalized media type, optional `ETag`/`Last-Modified`, byte count,
and local SHA-256.

### Fixed object identity

The TLC page's 2022 section linked exactly twelve monthly **Yellow Taxi Trip
Records (PARQUET)** objects. The same page linked the **Taxi Zone Lookup Table
(CSV)**. Those thirteen exact URLs form the intended source set:

Each target below is a binary object without an HTML page title. The displayed
names are the official TLC link labels, and TLC is the publishing agency that
links the CloudFront objects from its official landing page.

| Role | Exact official object URL | Bytes from HEAD | Last-Modified (UTC) | ETag observed |
|---|---|---:|---|---|
| Taxi-zone lookup | <https://d37ci6vzurychx.cloudfront.net/misc/taxi_zone_lookup.csv> | 12,331 | 2024-02-22 21:33:00 | `"c6064b7c144c716450641f769659d178"` |
| Yellow 2022-01 | <https://d37ci6vzurychx.cloudfront.net/trip-data/yellow_tripdata_2022-01.parquet> | 38,139,949 | 2022-06-30 03:16:20 | `"ec7d7ca1530dc0c4a3644914750fcd2a-3"` |
| Yellow 2022-02 | <https://d37ci6vzurychx.cloudfront.net/trip-data/yellow_tripdata_2022-02.parquet> | 45,616,512 | 2022-06-30 03:16:20 | `"3cdcb022ee65afdfe4b9b09b61603410-3"` |
| Yellow 2022-03 | <https://d37ci6vzurychx.cloudfront.net/trip-data/yellow_tripdata_2022-03.parquet> | 55,682,369 | 2022-06-30 03:16:20 | `"e0a3696392d949e495c125dffa8d8d46-4"` |
| Yellow 2022-04 | <https://d37ci6vzurychx.cloudfront.net/trip-data/yellow_tripdata_2022-04.parquet> | 55,222,692 | 2022-08-30 16:01:40 | `"bbc387175dc4092fea09039288b266ab-4"` |
| Yellow 2022-05 | <https://d37ci6vzurychx.cloudfront.net/trip-data/yellow_tripdata_2022-05.parquet> | 55,558,821 | 2022-08-30 16:01:40 | `"ffc506f258d02f2c9996f87175942449-4"` |
| Yellow 2022-06 | <https://d37ci6vzurychx.cloudfront.net/trip-data/yellow_tripdata_2022-06.parquet> | 55,365,184 | 2022-08-30 16:01:40 | `"3cb567412b90ab3a18714e17022ec3de-4"` |
| Yellow 2022-07 | <https://d37ci6vzurychx.cloudfront.net/trip-data/yellow_tripdata_2022-07.parquet> | 49,367,712 | 2022-11-14 13:55:37 | `"5e42a9d3bd1d770aaa0433a0bb38408e-3"` |
| Yellow 2022-08 | <https://d37ci6vzurychx.cloudfront.net/trip-data/yellow_tripdata_2022-08.parquet> | 49,717,159 | 2022-11-14 13:55:37 | `"e4eb255789a1c33f6d27916eb09e3a63-3"` |
| Yellow 2022-09 | <https://d37ci6vzurychx.cloudfront.net/trip-data/yellow_tripdata_2022-09.parquet> | 49,619,957 | 2022-11-30 20:24:30 | `"bf538be4999732af6952c4c108ea73ab-3"` |
| Yellow 2022-10 | <https://d37ci6vzurychx.cloudfront.net/trip-data/yellow_tripdata_2022-10.parquet> | 57,061,938 | 2022-12-19 21:59:12 | `"3a54d4dd190b9d9a14fa3aaeff371a59-4"` |
| Yellow 2022-11 | <https://d37ci6vzurychx.cloudfront.net/trip-data/yellow_tripdata_2022-11.parquet> | 50,106,631 | 2023-01-25 16:46:43 | `"04ba094635a1d2619f4bbb0c74123610-3"` |
| Yellow 2022-12 | <https://d37ci6vzurychx.cloudfront.net/trip-data/yellow_tripdata_2022-12.parquet> | 53,640,739 | 2023-03-20 20:46:51 | `"c4b29d86cdb68027eb1e24ea0f1ddc76-4"` |

All thirteen `HEAD` requests resolved with status 200. On 2026-08-23 the twelve
Parquet endpoints reported the unusual but consistent
`Content-Type: application/x-www-form-urlencoded; charset=utf-8`, while the
zone lookup reported `Content-Type: text/csv`. These are recorded transport
metadata, not format evidence: the local acquisition gate still verifies the
exact role, final URL, byte count, SHA-256, and parser contract. The TLC landing
page does not assign these objects a release tag or publish checksums, and the
Open Data terms warn that data can be updated, corrected, or refreshed. The
ETags, especially the multipart-looking values ending in `-3` or `-4`, must not
be reported as MD5 or SHA-256 digests.

The taxi-zone URL is unversioned, and its observed `Last-Modified` is in 2024.
The checked TLC page exposes no archived “2022 taxi-zone lookup” identity.
Consequently, the current CSV may be fixed as the study's lookup **as accessed
on 2026-08-23**, but it must not be called a “contemporaneous 2022 lookup”
without a separate first-party archived object or version record.

### First-party facts and citation recommendation

The TLC page says yellow and green taxi records contain pickup/drop-off dates,
times, and locations, among other fields. It says the attached data were
collected and provided to TLC by technology providers authorized under TPEP and
LPEP, were not created by TLC, and come with no TLC representation of accuracy.
It also says trip data are published monthly, typically after a two-month
delay, and are stored in Parquet because of their size. The currently linked
yellow-taxi dictionary defines `tpep_pickup_datetime`,
`tpep_dropoff_datetime`, `PULocationID`, and `DOLocationID`; it is current
documentation, not proof that every 2022 file has remained byte- or
schema-identical.

The checked official pages provide no dataset citation instruction and no
formal release date for the twelve-object set. This entry therefore uses the
official landing-page title and agency and omits author, year, and page numbers.

```bibtex
@misc{nyc_tlc_yellow_trip_records_2022,
  title        = {{TLC Trip Record Data}},
  howpublished = {New York City Taxi and Limousine Commission},
  url          = {https://www.nyc.gov/site/tlc/about/tlc-trip-record-data.page},
  note         = {Twelve monthly 2022 Yellow Taxi Trip Records Parquet objects
                  and the Taxi Zone Lookup Table CSV; accessed 2026-08-23}
}
```

If field semantics are material to the methods text, add a separate citation
to the official dictionary rather than silently treating the landing page as a
schema specification:

```bibtex
@misc{nyc_tlc_yellow_trip_data_dictionary,
  title        = {{Data Dictionary -- Yellow Taxi Trip Records}},
  howpublished = {New York City Taxi and Limousine Commission},
  url          = {https://www.nyc.gov/assets/tlc/downloads/pdf/data_dictionary_trip_records_yellow.pdf},
  note         = {Accessed 2026-08-23}
}
```

### License and use boundary

- NYC Open Data's FAQ says, “There are no restrictions on the use of Open
  Data,” and points readers to its Terms of Use.
- The TLC landing page presents the direct monthly files and links readers to
  the corresponding collection on NYC Open Data. No additional TLC-specific
  use condition is displayed on the checked landing page.
- The Technical Standards Manual grounds the policy in Local Law 11 of 2012:
  datasets are to be available without registration requirements, license
  requirements, or usage restrictions. It also says the City may require a
  third party that republishes a dataset or incorporates it into an application
  to identify the source, version, and modifications.
- The current Open Data Terms say users also agree to NYC.gov's Terms of Use and
  any additional agency terms. They disclaim completeness, accuracy, content,
  and fitness; disclaim City liability for deficiencies; identify submitting
  agencies as the authoritative sources; and say data may be updated,
  corrected, or refreshed at any time.
- This is an open-use policy, not a named CC0, Creative Commons, or Open Data
  Commons license. Cite the City/TLC source, record the exact object set and
  local hashes, describe transformations, and preserve the disclaimers. Do not
  infer permission to use City trademarks or unrelated NYC.gov page content.

### Manuscript claim boundary

Safe, when cited to the TLC page, dictionary, and Open Data terms as
appropriate:

- On 2026-08-23, the official TLC page linked twelve monthly 2022 yellow-taxi
  trip-record Parquet objects and one official taxi-zone lookup CSV at the
  exact URLs above.
- TLC describes the records as including pickup/drop-off dates, times, and
  locations, and the current official dictionary defines the four named time
  and location fields.
- The data were collected and provided to TLC by authorized technology
  providers; TLC says it did not create the trip data and makes no
  representation as to accuracy.
- NYC's Open Data pages state that Open Data has no use restrictions, subject
  to the cited terms and potential source/version/modification identification.
- “We derived a time-expanded origin-destination sparse matrix from these trip
  records” is safe as a statement of this study's transformation. Do not call
  that matrix a graph or benchmark supplied by TLC.

Do not state:

- that the thirteen-object set is an immutable, publisher-versioned “2022
  release” or that TLC published its checksums;
- that the unversioned lookup is a contemporaneous 2022 taxi-zone release;
- that the files are CC0, Creative Commons licensed, public domain, error-free,
  complete, or schema-frozen; or
- that TLC itself created the underlying trip observations.

## Acquisition-time publication checklist

Before any manuscript reports results from these sources:

1. Use the repository-owned downloader or CI transaction to acquire only the
   exact URLs listed here, fail closed on redirects to an unexpected object,
   request the identity representation, reject non-identity `Content-Encoding`
   and every `Content-Range`, and preserve digest-bound normalized observations
   of every contract-relevant response header. A data object requires one
   positive exact `Content-Length`. A terms object may record true absence as
   `null` and accept only a cleanly completed body of 1 through 2,097,152 bytes;
   a present terms-page length remains positive, within the cap, and exact. Never
   synthesize a missing header from the retained byte count. A caller-authored
   local manifest is not URL-to-byte acquisition authority.
2. Record retrieval UTC, final URL, byte count, `Last-Modified`, `ETag`, media
   type, and a locally computed SHA-256 for every object. Treat the local
   SHA-256, not an ETag, as the experiment's cryptographic identity.
3. Preserve a dated copy or digest of each applicable terms page because terms
   pages can change. Bind its retrieval UTC, no-fragment fetch URL, optional
   response validators, normalized media type, and any separately recorded
   section anchor.
4. Validate the expected file schema after acquisition; the present record
   verifies publisher descriptions and object availability, not payload
   contents.
5. Cite the exact dataset page/release and describe the study's transformation.
   For SNAP, also cite the source paper and avoid raw redistribution absent a
   separate terms determination. For Wikimedia, retain the 2026-07 object
   promptly because the official readme describes limited version retention.
   For TLC, identify the taxi-zone CSV as the lookup accessed on 2026-08-23,
   not as a publisher-versioned 2022 zone release.
6. Produce only acquisition transaction v3 and bind it through trace acquisition
   binding v2 and publication trace manifest v7. The two exact Stack Overflow
   terms URLs have a single frozen `curl_cffi==0.16.1` `chrome150` HTTP/2 route;
   there is no runtime fallback. Until the isolated runtime, post-run anchor, and
   ADR 0010 receipt are admitted, runtime/network/formal authority flags remain
   false.
7. Install acquisition and trace directories only through the repository-owned
   inode-bound, descriptor-relative no-replace seam, with exact verification
   before installation and same-inode revalidation afterward. Identity drift or
   a destination collision must return HOLD without a success receipt. Preserve
   rejected or incomplete staging trees whole under random diagnostic
   quarantine names after an identity-bound root claim; do not recursively
   unlink or remove staging entries through reusable pathnames. Treat this as a
   running-process atomic namespace guarantee, not as sudden-power-loss
   durability. The trace-preparation acquisition consumer must reopen and
   reverify one descriptor-bound exact-tree snapshot of that bundle before use.
