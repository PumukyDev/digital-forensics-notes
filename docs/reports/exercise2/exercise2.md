# Análisis de un informe pericial.

In digital forensics, producing a rigorous and well-structured expert report is essential to ensure both the technical and legal validity of the analysis. A sound report must not only accurately reflect the findings of the investigation, but also provide a clear framework that justifies the methodology used, the chain of custody of the evidence, and the conclusions reached. Clarity, coherence, and professionalism are key if the document is to be accepted as valid evidence in judicial or administrative proceedings.

When evaluating a forensic report, several essential aspects should be reviewed: a clear executive summary with conclusions; a detailed description of the case background; and the specific questions that motivated the expert examination. It is also necessary to identify digital evidence in a precise and technical manner — including its characteristics, origin, acquisition method, and preservation. The absence of these elements can undermine the objectivity and reliability of the report and weaken its probative value.

Other important criteria include appropriate technical language, sensitive-information marking using standards such as **TLP (Traffic Light Protocol)**, documented methodology, and properly referenced visual material. Reproducibility, traceability, and impartiality should guide any forensic report. Critical review is therefore a key practice both for professional improvement and for defending the work in legal settings.

In some cases, a forensic examiner may need to prepare a **counter-expert report**, either at the request of one of the parties or on the court's initiative when doubts arise about the original report. This requires a thorough review of the submitted report, evaluating both its formal structure and technical content, in order to identify gaps, methodological errors, chain-of-custody weaknesses, or unsupported conclusions.

### Objectives

- **Detect structural gaps:** identify missing key sections such as background, executive summary, or methodology.
- **Evaluate information protection:** verify appropriate TLP marking to ensure confidentiality.
- **Assess conclusion quality:** check whether the executive summary clearly answers the questions raised.
- **Analyze evidence handling:** review whether evidence is properly documented, preserved, and traceable.
- **Examine professional writing:** evaluate whether the language is objective, impersonal, and appropriate for expert work.
- **Identify technical and formal deficiencies:** check for unlabeled figures, missing tools, or undocumented methodology.
- **Assess counter-expert potential:** determine whether the report has weaknesses that could support a critical review or technical challenge.

### Report under review

This exercise analyzes the sample forensic report: ·[Informe-pericial-4.pdf](./Informe-pericial-4.pdf)

## Analysis

### Question 1: What is missing from the report?

Although the report includes recognizable sections (executive summary, background, objectives, analysis, and conclusions), several important elements are missing or underdeveloped:

**Methodology and reproducibility**
- No dedicated methodology chapter describing the scientific criteria followed before the analysis itself.
- Tools such as WinHex, Audacity, FOCA, EnCase, and iZotope RX are mentioned, but their **versions**, configuration, and step-by-step procedures are not documented.
- Without this level of detail, a third party cannot reliably repeat the examination.

**Case framing**
- The background of the case and the scope of the engagement are not clearly stated (who commissioned the work, why, and what questions the expert was asked to answer).
- Explicit **pericial questions** are absent (e.g., whether the video was edited, whether the audio was manipulated, whether the recording is authentic, whether the transcription is accurate).

**Chain of custody and evidence register**
- Sources are referenced, but there is no visible **chain-of-custody sheet** documenting who handed over the material, when, how it was stored, and what controls were applied.
- A formal evidence inventory table is missing.

**Other formal elements**
- No glossary of technical terms and abbreviations for non-specialist readers.
- No explicit **TLP** label on the cover or header, despite the sensitivity of the content.
- The limitations section exists in name only; it does not adequately address recording quality, ambient noise, compression loss, or what cannot be determined from the file alone.

### Question 2: What can you say about the report's TLP marking? What level would you assign?

The report does **not** use explicit TLP (Traffic Light Protocol) marking. None of the standard labels appear:

- TLP:CLEAR
- TLP:GREEN
- TLP:AMBER
- TLP:RED

This is a significant omission given the nature of the material, which includes:

- Full names and national ID numbers
- Judicial procedure data
- Statements from a protected witness
- Prosecutor and judge-related information
- Recordings from a courtroom environment

**Recommended classification: TLP:AMBER** as a minimum information may be shared only with parties who need it for the proceeding. Given the extreme sensitivity of witness-protection and judicial content, **TLP:RED** would also be defensible (restricted circulation, no public dissemination). In no case would **TLP:CLEAR** be appropriate.

### Question 3: What are the conclusions of the executive summary? What would you add, and on what basis?

**What the summary currently conveys**
- An authenticity analysis of the recording was performed.
- A partial transcription was produced.
- No clear signs of manipulation were identified.
- The recording is presented as maintaining its integrity.

**Weaknesses**
- The summary does not directly answer the commissioning questions in a structured way.
- It lacks a clear **Object → Procedure → Result → Conclusion** format.
- It does not foreground the most relevant technical findings — for example, evidence suggestive of **contamination of testimony**, such as WhatsApp notifications received during the session and third parties apparently prompting the protected witness.

**What should be added**
1. A numbered set of technical conclusions tied to observable findings (spectral analysis, synchronization tables, notification sounds, visual behaviour).
2. A qualified conclusion on manipulation: *no technical indicators consistent with editing were found in the file analyzed* — rather than absolute certainty.
3. An explicit limitation: conclusions apply to the **file received**; without a complete chain of custody, the expert cannot prove it is the original recording device output.

This last point is especially important because the report repeatedly states the video was not manipulated, while technically that claim cannot be fully guaranteed from the delivered file alone.

### Question 4: What do you think of the evidence identification?

Reviewers reached different conclusions on this point, which itself highlights an inconsistency in the report.

**Positive aspects**
- The main video file is identified and its MP4 format is stated.
- Some technical metadata appears in the analysis (duration, codecs, bit rates).
- Screenshots of tools (WinHex, hash utilities, frequency spectra) support traceability of certain steps.
- In places, integrity algorithms such as SHA-1 and SHA-256 are referenced.

**Critical weaknesses**
- There is no **formal evidence table** integrating hash values, file size, acquisition date/time, source device, and unique evidence identifiers in one place.
- Chain-of-custody details are insufficient to demonstrate that the analyzed file is the same object that left the source environment.
- Enumeration of all received material, creation timestamps, and preservation controls is incomplete.

**Overall assessment**
Evidence identification is **uneven**: some technical rigour appears within the analysis, but not at the level expected in a modern forensic report. A counter-expert could challenge admissibility on the grounds that integrity and custody are not systematically documented, even if individual hash screenshots exist in the body of the report.

### Question 5: What do you think of the language used?

The report generally uses professional and technically appropriate vocabulary, and complex concepts are explained in places with reasonable clarity.

However, several issues reduce its objectivity:

- **First-person phrasing** appears in sections where impersonal, descriptive language would be preferable in an expert report.
- **Overly categorical statements** are used, such as *"totally and absolutely impossible"*, *"there is no doubt"*, *"faithful and real"*, or claims that the analysis *"guarantees"* the file was not manipulated.
- Forensic practice normally works with **degrees of confidence** and observed indicators, not absolute certainty.
- Subjective value judgements occasionally appear where neutral technical description would be expected.

The language is acceptable in parts but should be more neutral, scientific, and cautious especially in conclusions.

### Question 6: What else stands out to you?

**Technical strengths**
- **Synchronization analysis:** comparative tables linking recording timeline and real courtroom time to show simultaneous events.
- **Acoustic detection:** identification of WhatsApp notification sounds and correlation with the behaviour of people present.
- **Visual traceability:** inclusion of tool screenshots (WinHex, spectra, etc.) that support reproducibility of specific steps.

**Structural concerns**
- A large portion of the report consists of a commented transcription of video fragments, giving it a more **argumentative** than strictly expert tone.
- Conclusions about non-manipulation sometimes appear **before** the final conclusions section, which may suggest confirmation bias.
- No mention of independent peer review or cross-validation of results.

**Practical implication**
The underlying technical work may be sound — the analysis appears to address whether the recording was edited and documents second-by-second observations — but **poor formal presentation** (missing systematic hashes, weak custody documentation, no TLP marking, overstated conclusions) could cause the report to carry less weight in court than the underlying analysis deserves.

**Counter-expert viability**
There are sufficient grounds to challenge the report on:

1. Incomplete chain of custody
2. Insufficient formal evidence identification
3. Missing or non-systematic integrity hashes
4. Under-documented methodology (tool versions, procedures)
5. Overly conclusive language
6. Inability to prove the analyzed file is the original recording
