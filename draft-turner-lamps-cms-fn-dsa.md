---
title: "Use of the FN-DSA Signature Algorithm in the Cryptographic Message Syntax (CMS)"
abbrev: "FN-DSA in the CMS"
category: std

docname: draft-ietf-lamps-cms-fn-dsa-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Limited Additional Mechanisms for PKIX and SMIME"
keyword:
  - CMS
  - FN-DSA
  - Falcon
  - PKIX
  - S/MIME
venue:
  group: "Limited Additional Mechanisms for PKIX and SMIME"
  type: "Working Group"
  mail: "spasm@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/spasm/"
  github: "lamps-wg/cms-fn-dsa"
  latest: "https://seanturner.github.io/cms-fn-dsa/draft-turner-lamps-cms-fn-dsa.html"

author:
#  -
#    fullname: Ben Salter
#    ins: B. Salter
#    organization: UK National Cyber Security Centre
#    email: ben.s3@ncsc.gov.uk
#  -
#    fullname: Adam Raine
#    ins: A. Raine
#    organization: UK National Cyber Security Centre
#    email: adam.r@ncsc.gov.uk
  -
    fullname: Daniel Van Geest
    ins: D. Van Geest
    organization: CryptoNext Security
    email: daniel.vangeest@cryptonext-security.com
  -
    fullname: Sean 
    ins: S. Turner
    organization: sn3rd
    email: sean@sn3rd.com

normative:
  FIPS206:
    title: "Fast Fourier Transform over NTRU-Lattice-Based Digital Signature Algorithm"
    target: https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards
  CSOR:
    target: https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
    title: Computer Security Objects Register
    author:
      name: National Institute of Standards and Technology
      ins: NIST
    date: 2024-08-20
  X690:
    target: https://www.itu.int/rec/T-REC-X.690
    title: >
      Information Technology -- Abstract Syntax Notation One (ASN.1):
      ASN.1 encoding rules: Specification of Basic Encoding Rules (BER),
      Canonical Encoding Rules (CER) and Distinguished Encoding Rules (DER)
    date: 2021-02
    author:
    -  org: ITU-T
    seriesinfo:
      ITU-T Recommendation: X.690
      ISO/IEC: 8825-1:2021

informative:
  X680:
    target: https://www.itu.int/rec/T-REC-X.680
    title: >
      Information Technology - Abstract Syntax Notation One (ASN.1):
      Specification of basic notation. ITU-T Recommendation X.680
      (2021) | ISO/IEC 8824-1:2021.
    date: 2021-02
    author:
      org: ITU-T
    seriesinfo:
      ITU-T Recommendation: X.680
      ISO/IEC: 8824-1:2021
---

--- abstract

The Fast-Fourier Transform over NTRU-Lattice-Based Digital Signature
Algorithm (FN-DSA), as defined by NIST in FIPS 206, is a post-quantum
digital signature scheme that aims to be secure against an adversary in
possession of a Cryptographically Relevant Quantum Computer (CRQC). This
document specifies the conventions for using the FN-DSA signature
algorithm with the Cryptographic Message Syntax (CMS). In addition, the
algorithm identifier is provided.


--- middle

# Introduction

The Fast-Fourier Transform over NTRU-Lattice-Based Digital Signature
Algorithm (FN-DSA) is a digital signature algorithm standardised by the
US National Institute of Standards and Technology (NIST) as part of
their post-quantum cryptography standardisation process. It is intended
to be secure against both "traditional" cryptographic attacks, as well
as attacks utilising a quantum computer. It offers smaller signatures
and significantly faster runtimes than SLH-DSA {{FIPS205}}, an
alternative post-quantum signature algorithm also standardised by NIST.
This document specifies the use of the FN-DSA in the CMS at two security
levels: FN-DSA-512 and FN-DSA-1024.  See Appendix B of I-D.turner-lamps-fn-dsa-certificates
for more information on the security levels and key sizes of FN-DSA.

Prior to standardisation, FN-DSA was known as Falcon.  FN-DSA and Falcon
are not compatible.

For each of the FN-DSA parameter sets, an algorithm identifier Object Identifier
(OID) has been specified.

## Conventions and Definitions

{::boilerplate bcp14-tagged}

# FN-DSA Algorithm Identifiers {#fn-dsa-algorithm-identifiers}

Many ASN.1 data structure types use the `AlgorithmIdentifier` type to
identify cryptographic algorithms. In the CMS, the `AlgorithmIdentifier`
field is used to identify FN-DSA signatures in the `signed-data` content
type. They may also appear in X.509 certificates used to verify those
signatures. The same `AlgorithmIdentifier` values are used to identify
FN-DSA public keys and signature algorithms. I-D.turner-lamps-fn-dsa-certificates
describes the use of FN-DSA in X.509 certificates.
The `AlgorithmIdentifier` type is defined as follows:

~~~ asn.1
AlgorithmIdentifier{ALGORITHM-TYPE, ALGORITHM-TYPE:AlgorithmSet} ::=
        SEQUENCE {
            algorithm   ALGORITHM-TYPE.&id({AlgorithmSet}),
            parameters  ALGORITHM-TYPE.
                   &Params({AlgorithmSet}{@algorithm}) OPTIONAL
        }
~~~

<aside markdown="block">
  NOTE: The above syntax is from {{?RFC5911}} and is compatible with the
  2021 ASN.1 syntax {{X680}}. See {{?RFC5280}} for the 1988 ASN.1 syntax.
</aside>

The fields in the `AlgorithmIdentifier` type have the following meanings:

`algorithm`:

: The `algorithm` field contains an OID that identifies the cryptographic
algorithm in use. The OIDs for FN-DSA are described below.

`parameters`:

: The `parameters` field contains parameter information for the algorithm
identified by the OID in the `algorithm` field. Each FN-DSA parameter set
is identified by its own algorithm OID, so there is no relevant
information to include in this field. As such, `parameters` MUST be omitted
when encoding an FN-DSA `AlgorithmIdentifier`.

The OIDs for FN-DSA are defined in the NIST Computer Security Objects
Register {{CSOR}}, and are reproduced here for convenience.

<aside markdown="block">
  TODO: NIST WILL ASSIGN THESE.
</aside>

~~~ asn.1
sigAlgs OBJECT IDENTIFIER ::= { joint-iso-itu-t(2) country(16)
    us(840) organization(1) gov(101) csor(3) nistAlgorithms(4) 3 }

id-fn-dsa-512 OBJECT IDENTIFIER ::= { sigAlgs TBD }

id-fn-dsa-87 OBJECT IDENTIFIER ::= { sigAlgs TBD }

~~~

# Signed-Data Conventions

## Pure Mode vs Pre-hash Mode {#pure-vs-pre-hash}

{{!RFC5652}} specifies that digital signatures for CMS are produced using
a digest of the message to be signed and the signer's private key. At
the time of publication of that RFC, all signature algorithms supported
in the CMS required a message digest to be calculated externally to that
algorithm, which would then be supplied to the algorithm implementation
when calculating and verifying signatures. Since then, EdDSA {{?RFC8032}},
ML-DSA {{?FIPS20=DOI.10.6028/NIST.FIPS.204}}, and SLH-DSA {{?FIPS205=DOI.10.6028/NIST.FIPS.205}},
have also been standardised, and these algorithms support both a "pure"
and "pre-hash" mode. In the pre-hash mode, a message digest (the "pre-hash")
is calculated separately and supplied to the signature algorithm as
described above. In the pure mode, the message to be signed or verified
is instead supplied directly to the signature algorithm. When EdDSA {{?RFC8419}},
SLH-DSA {{?RFC9814}}, and ML-DSA {{?RFC9882}} are used with CMS, only the
pure mode of those algorithms is specified. This is because in most
situations, CMS signatures are computed over a set of signed attributes
that contain a hash of the content, rather than being computed over the
message content itself. Since signed attributes are typically small, use
of pre-hash modes in the CMS would not significantly reduce the size of
the data to be signed, and hence offers no benefit. This document follows
that convention and does not specify the use of FL-DSA's pre-hash mode
("HashFN-DSA") in the CMS.

## Signature Generation and Verification

{{RFC5652}} describes the two methods that are used to calculate and
verify signatures in the CMS. One method is used when signed attributes
are present in the `signedAttrs` field of the relevant `SignerInfo`, and
another is used when signed attributes are absent. Each method produce
a different "message digest" to be supplied to the signature algorithm
in question, but because the pure mode of FN-DSA is used, the "message
digest" is in fact the entire message. Use of signed attributes is
preferred, but the conventions for `signed-data` without signed
attributes is also described below for completeness.

When signed attributes are absent, FN-DSA (pure mode) signatures are
computed over the content of the `signed-data`. As described in {{Section 5.4 of RFC5652}},
the "content" of a `signed-data` is the value of the
`encapContentInfo eContent OCTET STRING`. The tag and length octets are
not included.

When signed attributes are included, FN-DSA (pure mode) signatures are
computed over the complete DER {{X690}} encoding of the `SignedAttrs` value
contained in the `SignerInfo`'s `signedAttrs` field. As described in
{{Section 5.4 of RFC5652}}, this encoding includes the tag and length
octets, but an `EXPLICIT SET OF` tag is used rather than the `IMPLICIT \[0\]`
tag that appears in the final message. At a minimum, the `signedAttrs`
field MUST at minimum include a `content-type` attribute and a
`message-digest` attribute. The `message-digest` attribute contains a
hash of the content of the `signed-data`, where the content is as
described for the absent signed attributes case above. Recalculation
of the hash value by the recipient is an important step in signature
verification.

{{Section 4 of RFC9814}} describes how, when the content of a `signed-data`
is large, performance may be improved by including signed attributes.
This is as true for FN-DSA as it is for SLH-DSA, although FN-DSA
signature generation and verification is significantly faster than
SLH-DSA.

FN-DSA has a context string input that can be used to ensure that
different signatures are generated for different application contexts.
When using FN-DSA as specified in this document, the context string
is set to the empty string.

## SignerInfo Content

When using FN-DSA, the fields of a `SignerInfo` are used as follows:

<aside markdown="block">
  TODO: Include text on security strength.
</aside>

`digestAlgorithm`:

: Per {{Section 5.3 of RFC5652}}, the `digestAlgorithm` field identifies
the message digest algorithm used by the signer, and any associated
parameters. Each FN-DSA parameter set ...

<!-- Need something similar for FN-DSA. Not sure they use lamda.

 has a collision strength parameter, represented by the &lambda;
 (lambda) symbol in {{FIPS206}}. When signers utilise signed attributes,
 their choice of digest algorithm may impact the overall security
 level of their signature. Selecting a digest algorithm that offers
 &lambda; bits of security strength against second preimage attacks and
 collision attacks is sufficient to meet the security level offered by
 a given parameter set, so long as the digest algorithm produces at
 least 2 * &lambda; bits of output. The overall security strength
 offered by an ML-DSA signature calculated over signed attributes is
 the floor of the digest algorithm's strength and the strength of the
 FL-DSA parameter set. Verifiers MAY reject a signature if the signer's
 choice of digest algorithm does not meet the security requirements of
 their choice of ML-DSA parameter set.
-->

: {{fn-dsa-digest-algs}} shows appropriate SHA-2 and SHA-3 digest
algorithms for each parameter set.

: SHA-512 {{?FIPS180=DOI.10.6028/NIST.FIPS.180-4}} MUST be supported for use with the variants of
FN-DSA in this document. SHA-512 is suitable for all FN-DSA parameter
sets and provides an interoperable option for legacy CMS
implementations that wish to migrate to use post-quantum cryptography,
but that may not support use of SHA-3 derivatives at the CMS layer.
However, other hash functions MAY also be supported; in particular,
SHAKE256 SHOULD be supported, as this is the digest algorithm used
internally in FN-DSA. When SHA-512 is used, the id-sha512 {{!RFC5754}}
digest algorithm identifier is used and the parameters field MUST be
omitted. When SHAKE256 is used, the id-shake256 {{!RFC8702}} digest
algorithm identifier is used and the parameters field MUST be omitted.
SHAKE256 produces 512 bits of output when used as a message digest
algorithm in the CMS.

: When signing using FN-DSA without including signed attributes,
the algorithm specified in the `digestAlgorithm` field has no
meaning, as FN-DSA computes signatures over entire messages
rather than externally computed digests. As such, the
considerations above and in {{fn-dsa-digest-algs}} do not apply.
Nonetheless, in this case implementations MUST specify SHA-512 as
the `digestAlgorithm` in order to minimise the likelihood of an
interoperability failure. When processing a `SignerInfo` signed using
FN-DSA, if no signed attributes are present, implementations MUST
ignore the content of the `digestAlgorithm` field.

<aside markdown="block">
  TODO: Verify table entries.
</aside>

 | Signature Algorithm | Digest Algorithms                                                           |
 | FN-DSA-512          | SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256 |
 | FN-DSA-1024         | SHA-512, SHA3-512, SHAKE256                                                 |
 {: #fn-dsa-digest-algs title="Suitable Digest Algorithms for FN-DSA"}

`signatureAlgorithm`:

 : The `signatureAlgorithm` field MUST contain one of the FN-DSA
 signature algorithm OIDs, and the parameters field MUST be absent.
 The algorithm OID MUST be one of the following OIDs described in
 {{fn-dsa-algorithm-identifiers}}:

 | Signature Algorithm | Algorithm Identifier OID |
 | FN-DSA-512          | id-fn-dsa-512            |
 | FN-DSA-10124        | id-fn-dsa-1024           |
 {: #tab-oids title="Signature algorithm identifier OIDs for FN-DSA"}

<aside markdown="block">
  TODO: Verify paragraph references.
</aside>

 `signature`:

 : The `signature` field contains the signature value resulting from the
 use of the FN-DSA signature algorithm identified by the
 `signatureAlgorithm` field. The FN-DSA (pure mode) signature-generation
 operation is specified in Section X.X of {{FIPS206}}, and the
 signature-verification operation is specified in Section X.X of {{FIPS206}}.
 Note that {{Section 5.6 of RFC5652}} places further requirements on the
 successful verification of a signature.

# Security Considerations

The security considerations in {{RFC5652}} and I-D.turner-lamps-fn-dsa-certificates
apply to this specification.

Security of the FN-DSA private key is critical. Compromise of the private
key will enable an adversary to forge arbitrary signatures.

<aside markdown="block">
  TODO: Verify paragraph reference.
</aside>

FN-DSA depends on high quality random numbers that are suitable for use
in cryptography. The use of inadequate pseudo-random number generators
(PRNGs) to generate such values can significantly undermine the security
properties offered by a cryptographic algorithm. For instance, an
attacker may find it much easier to reproduce the PRNG environment that
produced any private keys, searching the resulting small set of
possibilities, rather than brute-force searching the whole key space.
The generation of random numbers of a sufficient level of quality for
use in cryptography is difficult; see Section X.X.X of {{FIPS206}} for
some additional information.

<aside markdown="block">
  TODO: Insert references for active research.
</aside>

By default, FN-DSA signature generation uses randomness from two
sources: fresh random data generated during signature generation, and
precomputed random data included in the signer's private key. This is
referred to as the "hedged" variant of FN-DSA. Inclusion of both
sources of random data can help mitigate against faulty random number
generators, side-channel attacks, and fault attacks. {{FIPS206}} also
permits creating deterministic signatures using just the precomputed
random data in the signer's private key. The same verification
algorithm is used to verify both hedged and deterministic signatures, so
this choice does not affect interoperability. The signer SHOULD NOT use
the deterministic variant of FN-DSA on platforms where side-channel
attacks or fault attacks are a concern. Side channel attacks and fault
attacks against FN-DSA are an active area of research XX XX.
Future protection against these styles of attack may involve
interoperable changes to the implementation of FN-DSA's internal
functions. Implementers SHOULD consider implementing such protection
measures if it would be beneficial for their particular use cases.

To avoid algorithm substitution attacks, the `CMSAlgorithmProtection`
attribute defined in {{!RFC6211}} SHOULD be included in signed
attributes.

# Operational Considerations

If FN-DSA signing is implemented in a hardware device such as a
hardware security module (HSM) or a portable cryptographic token,
implementers might want to avoid sending the full content to the
device for performance reasons. By including signed attributes,
which necessarily includes the `message-digest` attribute and the
`content-type` attribute as described in {{Section 5.3 of RFC5652}},
the much smaller set of signed attributes are sent to the device for
signing.

<!-- Assume we can delete the following:

Additionally, the pure variant of FN-DSA does support a form of pre-hash
via external calculation of the &mu; (mu) "message representative" value
described in Section X.X of {{FIPS206}}. This value may "optionally
be computed in a different cryptographic module" and supplied to the
hardware device, rather than requiring the entire message to be # transmitted.
Appendix D of {{?I-D.ietf-lamps-dilithium-certificates}} describes use of
external &mu; calculations in further detail.

-->

# IANA Considerations

For the ASN.1 module in {{asn1}}, IANA \[ is requested/has assigned \]
the following object identifier (OID) in the "SMI Security for S/MIME
Module Identifier" registry (1.2.840.113549.1.9.16.0):

| Decimal | Description        | Reference |
|:--------|:-------------------|:----------|
| TBD     | id-mod-fn-dsa-2026 | This RFC  |
{: #iana-reg title="Object Identifier Assignments"}

--- back

# ASN.1 Module {#asn1}

<aside markdown="block">
RFC EDITOR: Please replace the reference to I-D.turner-lamps-fn-dsa-certificates
in the ASN.1 module below with a reference the corresponding published RFC.
</aside>

~~~ asn.1
<CODE BEGINS>
{::include FN-DSA-Module-2026.asn}
<CODE ENDS>
~~~

# Examples

This appendix contains example `signed-data` encodings. They can be
verified using the example public keys and certificates specified in
Appendix C of I-D.turner-lamps-fn-dsa-certificates.

The following is an example of a `signed-data` with a single
FN-DSA-512 signer, with signed attributes included:

<aside markdown="block">
  TODO:  Get Example.
</aside>

The following is an example of a signed-data with a single
FN-DSA-1024 signer, with signed attributes included:

<aside markdown="block">
  TODO:  Get Example.
</aside>

# Acknowledgments
{:numbered="false"}

<aside markdown="block">
  TODO:
</aside>

This document was heavily influenced by {{?RFC8419}}, {{RFC9814}}, and
{{RFC9881}}. Thanks go to the authors of those documents.
