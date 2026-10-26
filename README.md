# MVS BOT — Mainframe Compatibility & PTF Analyzer

A local Streamlit MVP for investigating mainframe software compatibility against z/OS 2.5, 3.1 and 3.2. It is designed to be vendor-neutral and includes a configurable vendor source registry, product lookup, Excel/CSV inventory intake, page-limited same-domain crawling, evidence display, session research history and Excel/CSV report exports.

## Quick start (Windows)
1. Install Python 3.10 or later.
2. Extract the ZIP.
3. Open Command Prompt/PowerShell in the `mvs_bot` folder.
4. Run:
   ```powershell
   py -m venv .venv
   .venv\Scripts\activate
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   streamlit run app.py
   ```
5. Open the local URL printed by Streamlit.

macOS/Linux:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

## Features
- Product lookup with vendor, exact release, target z/OS versions and configurable official source URLs.
- A respectful crawler with page limits, same-domain link traversal, delays, cache, and a robots.txt check. It skips a URL if robots permission cannot be confirmed.
- HTML and PDF text extraction; heuristic PTF/APAR candidate extraction; page excerpts, source URLs and content hashes.
- Excel/CSV input validation and compatibility matrix expansion.
- Vendor registry seeded with IBM, Broadcom, BMC, Rocket/ASG, OpenText/Micro Focus, Precisely, UNICOM and an “Other” category.
- Excel report with Compatibility, Source Evidence, and Manual Review sheets; CSV downloads.
- Bundled seed catalogs copied from the three user-provided CSVs.

## Included data
`data/asg_compat.csv`, `data/bmc_compat.csv`, and `data/broadcom_compat.csv` are the provided seed catalogs. They are reference input only; they are not automatically treated as verified current compatibility data.

## Important limitations
- This is a starter application, not a fully autonomous web-wide search engine. Add official source URLs in Vendor Registry or Product Lookup. It follows same-domain links only and obeys the robots check; ten page attempts are not guaranteed to yield ten successful or relevant pages.
- It does not bypass logins, paywalls, customer entitlements, CAPTCHAs, robots restrictions or vendor access controls. Some PAC/support portals need authorized APIs or credentials and should be integrated separately with permission.
- PTF/APAR parsing and compatibility status are heuristic candidates, not authoritative decisions. A PTF mentioned on a page may not apply to the selected product/release or z/OS level. All output remains subject to human verification.
- The current bulk workflow creates a matrix with `Unknown`; it does not automatically run research for every inventory row. Bulk research orchestration and a persistent database are next-phase work.
- Session history is not persisted after a Streamlit session ends.
- Review applicable vendor terms, robots.txt, rate limits and security requirements before deployment. Do not use this app as an installation approval system.

## Suggested production roadmap
1. Add a proper search provider/API for discovery across vendors.
2. Build vendor-specific adapters and structured parsers for official compatibility matrices, PDFs, release notes and support APIs.
3. Add per-product/per-release batch orchestration with job queue, retry handling, persistent PostgreSQL evidence store and incremental recrawls.
4. Require traceable evidence for every Yes/No/Conditional decision; keep Unknown when evidence is absent or conflicting.
5. Add automated tests, authentication, audit logs, access controls, deployment configuration and a human approval workflow.

## Suggested inventory columns
`Vendor`, `Product`, `Release`, `Product ID` (optional), `Notes` (optional).
