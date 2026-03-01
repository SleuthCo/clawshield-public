---
framework: "Open Source Intelligence (OSINT)"
version: "1.0"
domain: "Intelligence Gathering"
agent: "coda"
tags: ["osint", "intelligence", "search-operators", "social-media", "reconnaissance", "investigation"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

## OSINT Fundamentals and Legal Framework

Open Source Intelligence (OSINT) is intelligence derived from publicly available information that is collected, exploited, and disseminated in a timely manner to an appropriate audience for the purpose of addressing a specific intelligence requirement. The key distinction is that OSINT uses only legally accessible, publicly available sources.

Legal boundaries vary by jurisdiction but generally include: no unauthorized access to computer systems (CFAA in the US, Computer Misuse Act in the UK), no creation of fake identities to deceive (may constitute fraud), compliance with terms of service (breach may create civil liability), data protection regulations (GDPR right to be forgotten, CCPA), and no harassment or stalking. Always document the legal basis for collection activities.

The OSINT cycle mirrors the intelligence cycle: requirements definition (what do you need to know?), source identification (where might the information exist?), collection (systematic gathering), processing (organization and filtering), analysis (deriving meaning), and dissemination (reporting to stakeholders).

Operational security (OPSEC) for the researcher is critical. Use VPNs or Tor for anonymous browsing, dedicated research machines or virtual machines, sock puppet accounts that cannot be traced back, browser compartmentalization, and metadata scrubbing on any documents you share. Your investigation should not alert the subject or compromise your identity.

## Advanced Search Engine Operators

Google advanced operators enable precision searching far beyond basic queries.

**Site and URL operators**: `site:example.com` restricts to a domain. `inurl:admin` finds pages with "admin" in the URL. `intitle:"index of"` finds directory listings. `filetype:pdf` or `ext:xlsx` targets specific file types. Combine these: `site:company.com filetype:pdf "confidential"` finds PDFs marked confidential on a specific domain.

**Content operators**: `intext:"exact phrase"` searches body text. `allintitle:word1 word2` requires all words in the title. `AROUND(n)` finds words within n words of each other (e.g., `CEO AROUND(3) resigned`). The minus operator `-word` excludes terms.

**Cache and time operators**: `cache:url` shows Google's cached version. `before:2024-01-01` and `after:2023-01-01` filter by date. These are useful for finding content that has been removed or changed.

**Google Dorks for reconnaissance**: `site:example.com inurl:login` finds login pages. `site:example.com ext:sql | ext:db | ext:log` finds database or log files. `"powered by" "version"` identifies software versions. The Google Hacking Database (GHDB) maintains categorized dorks for common targets.

**Beyond Google**: Bing has unique operators (`instreamset:url:` for streaming content). Yandex excels at reverse image search for Eastern European content. DuckDuckGo bangs (`!w` for Wikipedia, `!gh` for GitHub) provide quick access to specialized searches. Baidu is essential for Chinese-language content.

## Social Media Investigation Techniques

Each platform requires tailored approaches due to different data structures, privacy settings, and search capabilities.

**Twitter/X investigation**: Advanced search at twitter.com/search-advanced allows filtering by user, date range, engagement, and location. Use operators: `from:username`, `to:username`, `since:2024-01-01`, `until:2024-06-01`, `geocode:lat,long,radius`, `min_retweets:100`. Archived tweets can be found via the Wayback Machine, cached versions, or third-party archives. Analyze follower networks, interaction patterns, and temporal posting patterns for behavioral insights.

**LinkedIn investigation**: LinkedIn restricts search for non-premium users. Use Google dorking: `site:linkedin.com/in/ "company name" "job title"`. LinkedIn Sales Navigator provides advanced filtering. Extract organizational structures by mapping employee connections. Job postings reveal technology stacks, team sizes, and strategic priorities. Patent filings linked to employees indicate R&D directions.

**Facebook investigation**: Graph Search has been deprecated, but URL manipulation still works for some queries. Public posts, groups, and pages remain searchable. Facebook's transparency tools show ad spending and page management history. Check-ins, event attendance, and group memberships reveal behavioral patterns and associations.

**Instagram investigation**: User IDs persist even when usernames change. Stories and live videos are ephemeral but may be archived by third-party services. Location tags, hashtags, and tagged users provide network and movement information. Analyze posting frequency, engagement patterns, and follower demographics.

**Username enumeration**: Tools like Sherlock, WhatsMyName, and Namechk check username availability across hundreds of platforms. Consistent usernames across platforms enable cross-platform correlation. Variations and historical usernames can be found through cached pages and archived profiles.

## Domain and IP Reconnaissance

Domain investigation reveals ownership, infrastructure, and relationships between entities.

**WHOIS and registration data**: WHOIS records show registrant, administrative, and technical contacts (though GDPR has redacted many records). Historical WHOIS data from services like DomainTools, WhoisXML API, or SecurityTrails reveals past ownership. Registration dates, nameserver changes, and registrar transfers tell a story about domain history.

**DNS reconnaissance**: DNS records map the infrastructure. A records show IP addresses, MX records reveal email providers, TXT records may contain SPF/DKIM/DMARC configurations and domain verification tokens (e.g., Google, Microsoft). NS records show hosting providers. Use `dig`, `nslookup`, or online tools like DNSdumpster, SecurityTrails, or VirusTotal for passive DNS.

**Certificate transparency**: CT logs (crt.sh, Censys) record every SSL/TLS certificate issued. Searching by domain reveals subdomains, related domains, and organizational information embedded in certificates. Wildcard certificates indicate domain structures. Certificate timelines show when services were deployed.

**IP analysis**: Reverse DNS reveals hostnames assigned to IPs. IP geolocation provides approximate physical location. ASN (Autonomous System Number) lookup identifies the hosting provider or network owner. Shodan, Censys, and ZoomEye index internet-connected devices and reveal services, software versions, and configurations. BGP routing data from RIPE, ARIN, and other RIRs shows network ownership and peering relationships.

**Subdomain enumeration**: Active techniques (DNS brute-forcing) and passive techniques (certificate transparency, search engine indexing, VirusTotal, SecurityTrails). Tools: Sublist3r, Amass, subfinder. Subdomains often reveal internal naming conventions, development environments, and forgotten services.

## Public Records and Government Data

Government databases are rich OSINT sources, though access varies by jurisdiction.

**Corporate records**: SEC EDGAR (US public company filings — 10-K, 10-Q, 8-K, proxy statements, insider trading reports). Companies House (UK). State-level business registries. Annual reports, beneficial ownership filings, and corporate officer records reveal organizational structures and key personnel.

**Court records**: PACER (US federal courts), state court systems, RECAP (free archive of PACER documents). Court filings reveal disputes, financial difficulties, regulatory actions, and relationships between entities. Bankruptcy filings contain detailed financial information.

**Property records**: County assessor and recorder databases. Property ownership, transaction history, tax assessments, liens, and mortgages are typically public. Useful for identifying assets, shell companies, and connections between entities.

**Campaign finance**: FEC (US federal elections), state election commissions. Donor records reveal political affiliations, networks, and financial capacity. PAC contributions and lobbying disclosures show organizational political activities.

**International records**: OpenCorporates aggregates company data globally. Offshore leaks databases (ICIJ). EU business registers. UN sanctions lists. Interpol notices. World Bank debarment lists. OFAC (US Treasury) sanctions data.

## OSINT Tools and Workflows

A structured workflow prevents missed sources and ensures reproducibility.

**Collection tools by category**:
- Search and archiving: Hunchly (web capture), Wayback Machine, Archive.today, SingleFile browser extension
- Social media: Twint (Twitter without API), Instaloader (Instagram), Social-Analyzer, snscrape
- Domain/infrastructure: Maltego, SpiderFoot, Recon-ng, theHarvester, FOCA (metadata extraction)
- Geospatial: Google Earth Pro, Sentinel Hub (satellite imagery), SunCalc (sun position for photo verification)
- Visual: TinEye, Google Reverse Image Search, Yandex Images, FotoForensics (ELA analysis)
- People search: Pipl, ThatsThem, social media aggregators (jurisdiction-dependent legality)

**Workflow structure**: Begin with a seed — a name, email, phone number, username, domain, or IP address. Pivot from each finding to discover connected entities. Document every step in a structured format: source URL, timestamp, data found, and relationship to the investigation. Use a link-analysis tool (Maltego, i2 Analyst's Notebook, or a simple graph database) to map connections.

**Verification**: Every piece of OSINT must be verified through independent sources before being treated as fact. Apply the two-source rule minimum. Check for fabrication indicators: reverse image search photos, verify claimed credentials, cross-reference dates and locations, and check for copy-pasted content from other profiles.

## Digital Footprint Analysis

A digital footprint is the trail of data a person or organization leaves through online activity.

**Email investigation**: Verify email validity with tools like Hunter.io or Email Hippo. Search for the email across breach databases (Have I Been Pwned — for ethical, defensive purposes only). Email headers reveal originating IP addresses, mail servers, and routing. Google the email address with and without the domain to find associated accounts and posts.

**Phone number investigation**: Carrier lookup identifies the provider and whether the number is mobile, landline, or VoIP. Reverse phone lookup services vary by country. Phone numbers are often linked to messaging apps (WhatsApp, Telegram, Signal) which may reveal profile photos and display names. Caller ID databases and spam reporting sites contain user-contributed information.

**Image analysis**: EXIF metadata may contain GPS coordinates, camera model, timestamps, and software used. Tools: ExifTool, Jeffrey's Image Metadata Viewer. Reverse image search (Google, TinEye, Yandex) finds other instances of the same image. Error Level Analysis (ELA) can indicate manipulation. Geolocation from visual clues (landmarks, signage, vegetation, sun position, shadows) is a specialized skill — resources include Bellingcat's geolocation guides and GeoGuessr-style training.

**Archival research**: The Wayback Machine (web.archive.org) stores historical snapshots of websites. Use it to find deleted content, track changes over time, and recover removed pages. Archive.today provides on-demand snapshots. Google Cache stores recent versions. CachedView aggregates multiple cache sources.

## OSINT for Organizational Investigation

Investigating organizations requires mapping structure, activities, finances, and relationships.

**Corporate structure mapping**: Start with official filings to identify subsidiaries, parent companies, and officers. Cross-reference with beneficial ownership registries where available. Map board interlocks (shared directors between companies). Identify registered agents and their other clients.

**Financial investigation OSINT**: Public company financials from SEC EDGAR or equivalent. Charity/nonprofit filings (IRS Form 990 in the US — contains salaries, major donors, grants). Government contracts (USAspending.gov, FPDS). Procurement records. Aid and grant databases. Sanctions screening against OFAC, EU, and UN lists.

**Technology stack identification**: BuiltWith, Wappalyzer, and W3Techs identify web technologies. Job postings reveal internal technology choices. GitHub repositories may expose internal tools, configurations, or credentials. Stack Overflow questions from company email addresses reveal technical challenges.

**Supply chain and partner mapping**: SEC filings often disclose major customers and suppliers. Import/export records (Panjiva, ImportGenius) reveal trading relationships. Patent filings show technology partnerships and licensing. Conference sponsorships, trade show exhibitor lists, and industry association memberships reveal ecosystem positioning.

## Documentation and Evidence Preservation

OSINT findings must be documented to a standard that supports later analysis, reporting, and potentially legal proceedings.

**Evidence preservation**: Screenshot with full URL visible and timestamp. Save complete web pages (MHTML, SingleFile, or Hunchly). Archive URLs on the Wayback Machine and Archive.today. Hash files (SHA-256) immediately after collection to prove integrity. Maintain chain of custody documentation.

**Note-taking structure**: For each finding, record: date and time of collection, source URL, search query or method used, content found (verbatim or screenshot), relevance to the investigation, confidence level, and cross-references to other findings.

**Reporting OSINT**: Distinguish clearly between facts (directly observed in sources), assessments (analytical judgments based on facts), and assumptions (unstated beliefs underlying the analysis). Cite every source specifically. Rate source reliability (A-F) and information credibility (1-6) using standard intelligence community scales. Present findings in order of confidence and relevance, not in order of collection.
