from __future__ import annotations
import io, re, time, json, hashlib, urllib.parse, urllib.robotparser
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import requests
import streamlit as st
from bs4 import BeautifulSoup

try:
    from pypdf import PdfReader
except Exception:
    PdfReader = None

APP_DIR = Path(__file__).resolve().parent
DATA_DIR = APP_DIR / 'data'
DATA_DIR.mkdir(exist_ok=True)
ZOS_VERSIONS = ['2.5', '3.1', '3.2']
ZOS_ALIASES = {
    '2.5': ['z/os v2r5', 'z/os 2.5', 'zos 2.5', 'v2r5'],
    '3.1': ['z/os v3r1', 'z/os 3.1', 'zos 3.1', 'v3r1'],
    '3.2': ['z/os v3r2', 'z/os 3.2', 'zos 3.2', 'v3r2'],
}
PTF_RE = re.compile(r'\b(?:U[JNST]\d{5,7}|[A-Z]{2,3}\d{4,7}|LU\d{5,7}|PTF\s+[A-Z0-9]{5,10})\b', re.I)
APAR_RE = re.compile(r'\b(?:OA|PH|PI|PQ|PK|PM|PE|SA|SI|SW|II|BC|BMC|QF)\d{5,7}\b', re.I)
DEFAULT_REGISTRY = {
    'IBM': ['https://www.ibm.com/docs/en/zos', 'https://www.ibm.com/support/fixcentral/'],
    'Broadcom': ['https://ftpdocs.broadcom.com/WebInterface/phpdocs/0/MSPSaccount/COMPAT/zos_compat.HTML'],
    'BMC': ['https://www.bmc.com/support/resources/os390-and-zos-compatibilty.html', 'https://www.bmc.com/support/resources/day-one-support.html'],
    'Rocket Software / ASG': ['https://www.rocketsoftware.com/', 'https://community.rocketsoftware.com/product-updates'],
    'OpenText / Micro Focus': ['https://www.opentext.com/', 'https://docs.microfocus.com/'],
    'Precisely': ['https://www.precisely.com/'],
    'UNICOM': ['https://www.unicomglobal.com/'],
    'Other / discovered vendor': [],
}
USER_AGENT = 'MVS-BOT-Research/1.0 (+respectful, page-limited compatibility research)'

st.set_page_config(page_title='MVS BOT | Compatibility & PTF Analyzer', page_icon='🖥️', layout='wide')
st.markdown('''<style>
.main {background:#f5f8fc}.block-container{padding-top:1.2rem;max-width:1600px}
[data-testid="stSidebar"]{background:#0b1f38}
[data-testid="stSidebar"] *{color:#f5f8ff}
div[data-testid="stMetric"]{background:white;border:1px solid #dce6f2;padding:14px;border-radius:10px}
</style>''', unsafe_allow_html=True)

@st.cache_data(ttl=1800, show_spinner=False)
def fetch_page(url: str):
    headers = {'User-Agent': USER_AGENT}
    response = requests.get(url, headers=headers, timeout=20, allow_redirects=True)
    response.raise_for_status()
    ctype = response.headers.get('Content-Type', '').lower()
    if 'pdf' in ctype or response.url.lower().endswith('.pdf'):
        if PdfReader is None:
            raise RuntimeError('PDF found. Install pypdf to extract PDF text.')
        reader = PdfReader(io.BytesIO(response.content))
        text = ' '.join((page.extract_text() or '') for page in reader.pages[:60])
        return re.sub(r'\s+', ' ', text), [], response.url.split('/')[-1] or 'PDF document', response.url
    soup = BeautifulSoup(response.text, 'html.parser')
    title = soup.title.get_text(' ', strip=True) if soup.title else response.url
    for node in soup(['script', 'style', 'noscript', 'svg', 'nav', 'footer']):
        node.decompose()
    text = re.sub(r'\s+', ' ', soup.get_text(' ', strip=True))
    links = []
    base_host = urllib.parse.urlparse(response.url).netloc.lower()
    for a in soup.find_all('a', href=True):
        href = urllib.parse.urljoin(response.url, a['href'].strip())
        parsed = urllib.parse.urlparse(href)
        if parsed.scheme in ('http', 'https') and parsed.netloc.lower() == base_host:
            label = a.get_text(' ', strip=True)[:180]
            if not any(x in parsed.path.lower() for x in ['logout', 'signout', 'javascript:']):
                links.append((label, href.split('#')[0]))
    return text, links, title, response.url

def robots_allowed(url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    robots_url = f'{parsed.scheme}://{parsed.netloc}/robots.txt'
    rp = urllib.robotparser.RobotFileParser()
    try:
        rp.set_url(robots_url); rp.read()
        return rp.can_fetch(USER_AGENT, url)
    except Exception:
        # If robots.txt cannot be retrieved, do not treat that as blanket permission.
        return False

def context_for(text: str, aliases: list[str], radius: int = 350) -> str:
    low = text.lower()
    for alias in aliases:
        idx = low.find(alias.lower())
        if idx >= 0:
            return text[max(0, idx-radius):min(len(text), idx+radius)]
    return ''

def classify_context(context: str) -> str:
    if not context:
        return 'Unknown'
    s = context.lower()
    negative = re.search(r'\b(not supported|unsupported|not compatible|incompatible|no support|not available)\b', s)
    positive = re.search(r'\b(supported|compatible|certified|yes)\b', s)
    conditional = re.search(r'\b(conditional|with ptf|requires ptf|requires maintenance|planned|under review|tbd|to be determined)\b', s)
    if negative: return 'No (review evidence)'
    if conditional: return 'Conditional / Review'
    if positive: return 'Potential Yes — verify'
    return 'Unknown'

def page_evidence(url: str, product: str, release: str):
    text, links, title, final_url = fetch_page(url)
    terms = [x.strip() for x in [product, release] if x and x.strip()]
    relevant = (not terms) or all(term.lower() in text.lower() for term in terms) or any(term.lower() in text.lower() for term in terms)
    ptfs = sorted(set(x.upper().replace('PTF ', '') for x in PTF_RE.findall(text)))
    apars = sorted(set(x.upper() for x in APAR_RE.findall(text)))
    statuses, excerpts = {}, {}
    for version, aliases in ZOS_ALIASES.items():
        snippet = context_for(text, aliases)
        statuses['z/OS ' + version] = classify_context(snippet)
        excerpts['Evidence ' + version] = snippet[:700]
    digest = hashlib.sha256(text.encode('utf-8', errors='ignore')).hexdigest()[:16]
    return {'Page title': title, 'URL': final_url, 'Relevant': 'Yes' if relevant else 'Review',
            'PTF candidates': ', '.join(ptfs) if ptfs else 'None extracted',
            'APAR candidates': ', '.join(apars) if apars else 'None extracted',
            'Text excerpt': text[:1200], 'Content hash': digest, **statuses, **excerpts}, links

def crawl(seeds: list[str], product: str, release: str, max_pages: int, delay: float = 0.5):
    queue = deque((u, 0) for u in seeds if u.startswith(('http://','https://')))
    seen, records = set(), []
    while queue and len(seen) < max_pages:
        url, depth = queue.popleft()
        url = url.split('#')[0]
        if url in seen: continue
        seen.add(url)
        if not robots_allowed(url):
            records.append({'Page title':'Skipped by robots policy or robots.txt unavailable','URL':url,'Relevant':'No','PTF candidates':'Not checked','APAR candidates':'Not checked','Text excerpt':'URL was not fetched because robots permission could not be confirmed.','Content hash':'',**{'z/OS '+v:'Unknown' for v in ZOS_VERSIONS}})
            continue
        try:
            rec, links = page_evidence(url, product, release)
            records.append(rec)
            if depth < 2:
                scored = []
                for label, link in links:
                    if link in seen: continue
                    score = sum(word in (label+' '+link).lower() for word in ['compat','ptf','apar','release','maintenance','support','product','zos','fix','install','program temporary fix'])
                    if score: scored.append((score, label, link))
                for _, _, link in sorted(scored, reverse=True)[:max_pages]:
                    if len(queue) < max_pages * 4: queue.append((link, depth+1))
        except Exception as exc:
            records.append({'Page title':'Fetch error / inaccessible','URL':url,'Relevant':'Unknown','PTF candidates':'Unknown','APAR candidates':'Unknown','Text excerpt':str(exc)[:500],'Content hash':'',**{'z/OS '+v:'Unknown' for v in ZOS_VERSIONS}})
        time.sleep(delay)
    return records, list(seen)

def workbook_bytes(compat: pd.DataFrame, evidence: pd.DataFrame, input_df: pd.DataFrame | None = None) -> bytes:
    buffer = io.BytesIO()
    with pd.ExcelWriter(buffer, engine='openpyxl') as writer:
        compat.to_excel(writer, index=False, sheet_name='Compatibility')
        evidence.to_excel(writer, index=False, sheet_name='Source Evidence')
        if input_df is not None: input_df.to_excel(writer, index=False, sheet_name='Input Inventory')
        review = compat[compat.get('Compatible', pd.Series(dtype=str)).astype(str).str.contains('Unknown|Review|Conditional', case=False, na=True)] if not compat.empty else pd.DataFrame()
        review.to_excel(writer, index=False, sheet_name='Manual Review')
        for ws in writer.book.worksheets:
            ws.freeze_panes = 'A2'; ws.auto_filter.ref = ws.dimensions
            for col in ws.columns:
                max_len = min(60, max(12, max((len(str(c.value or '')) for c in list(col)[:200]), default=12) + 2))
                ws.column_dimensions[col[0].column_letter].width = max_len
    return buffer.getvalue()

def load_seed_data():
    frames=[]
    for filename in ['asg_compat.csv','bmc_compat.csv','broadcom_compat.csv']:
        p = APP_DIR / 'data' / filename
        if p.exists():
            try:
                d = pd.read_csv(p); d['Seed file'] = filename; frames.append(d)
            except Exception: pass
    return pd.concat(frames, ignore_index=True, sort=False) if frames else pd.DataFrame()

st.title('🖥️ MVS BOT')
st.caption('Mainframe Software Compatibility & PTF Analyzer • all-vendor source registry • z/OS 2.5 / 3.1 / 3.2')
st.warning('Research tool, not installation approval. Extracted PTFs are candidates until verified against the exact product release, vendor instructions, SMP/E HOLDDATA and applicable FIXCAT requirements.')

if 'registry' not in st.session_state:
    st.session_state.registry = {k:list(v) for k,v in DEFAULT_REGISTRY.items()}
if 'history' not in st.session_state: st.session_state.history = []
if 'evidence' not in st.session_state: st.session_state.evidence = pd.DataFrame()
if 'compatibility' not in st.session_state: st.session_state.compatibility = pd.DataFrame()

lookup_tab, upload_tab, registry_tab, history_tab, reports_tab = st.tabs(['🔎 Product Lookup','📤 Excel Bulk Upload','🏢 Vendor Registry','🕘 Research History','📊 Reports'])
with lookup_tab:
    st.subheader('Investigate a product')
    c1,c2,c3=st.columns([1,2,1])
    with c1: vendor = st.selectbox('Vendor', list(st.session_state.registry.keys()) + ['Add vendor / other'])
    with c2: product = st.text_input('Product name', placeholder='e.g. Db2, MainView, CA 7, TMON')
    with c3: release = st.text_input('Product release / VRM', placeholder='Exact release recommended')
    targets = st.multiselect('Target z/OS versions', ZOS_VERSIONS, default=ZOS_VERSIONS)
    default_urls = st.session_state.registry.get(vendor, [])
    source_text = st.text_area('Official documentation seed URLs (one per line)', '\n'.join(default_urls), height=100, help='Add official product compatibility, release notes, PTF, APAR, installation and support pages. Crawler follows same-domain links only.')
    col1,col2=st.columns([1,3])
    with col1: max_pages = st.slider('Page limit', 1, 50, 10, help='Maximum URL attempts, not a guarantee of ten successful reads.')
    with col2: st.caption('The crawler checks robots.txt before fetching and skips URLs when permission cannot be confirmed. Login-protected pages are not bypassed.')
    if st.button('Start compatibility research', type='primary', use_container_width=True):
        if not product.strip(): st.error('Enter a product name.')
        elif not source_text.strip(): st.error('Add at least one official documentation URL for this vendor.')
        else:
            seeds=[x.strip() for x in source_text.splitlines() if x.strip().startswith(('http://','https://'))]
            with st.spinner(f'Checking up to {max_pages} URLs for {product}…'):
                records, visited = crawl(seeds, product.strip(), release.strip(), max_pages)
            ev = pd.DataFrame(records)
            st.session_state.evidence = ev
            rows=[]
            for version in targets:
                column='z/OS '+version
                matched = ev[ev.get('Relevant', pd.Series(index=ev.index,dtype=str)).eq('Yes')] if not ev.empty else ev
                statuses = matched[column].astype(str).tolist() if not matched.empty and column in matched else []
                if any(s.startswith('No') for s in statuses): result='No — evidence requires review'
                elif any(s.startswith('Conditional') for s in statuses): result='Conditional / Review'
                elif any(s.startswith('Potential Yes') for s in statuses): result='Potential Yes — verify'
                else: result='Unknown'
                ptfs = sorted(set(x.strip() for val in (matched.get('PTF candidates', []) if not matched.empty else []) for x in str(val).split(',') if x.strip() and x.strip()!='None extracted'))
                apars = sorted(set(x.strip() for val in (matched.get('APAR candidates', []) if not matched.empty else []) for x in str(val).split(',') if x.strip() and x.strip()!='None extracted'))
                urls = matched['URL'].dropna().astype(str).tolist() if not matched.empty and 'URL' in matched else []
                rows.append({'Vendor':vendor,'Product':product.strip(),'Release':release.strip(),'z/OS version':version,'Compatible':result,'PTF required / candidates':'; '.join(ptfs) if ptfs else 'Unknown — not verified','APAR candidates':'; '.join(apars) if apars else 'Unknown','Evidence URL(s)':'\n'.join(urls),'Evidence status':'Needs human verification','Pages attempted':len(visited),'Checked UTC':datetime.now(timezone.utc).isoformat()})
            comp=pd.DataFrame(rows); st.session_state.compatibility=comp
            st.session_state.history.append({'Vendor':vendor,'Product':product.strip(),'Release':release.strip(),'Pages attempted':len(visited),'Records':len(ev),'Checked UTC':datetime.now(timezone.utc).isoformat()})
            st.success(f'Investigation finished: {len(visited)} URL attempts, {len(ev)} evidence records. Results are provisional.')
    if not st.session_state.compatibility.empty:
        st.subheader('Compatibility results')
        st.dataframe(st.session_state.compatibility, use_container_width=True, hide_index=True)
        if not st.session_state.evidence.empty:
            st.subheader('Evidence pages actually attempted')
            st.dataframe(st.session_state.evidence, use_container_width=True, hide_index=True, column_config={'URL':st.column_config.LinkColumn('Source URL')})

with upload_tab:
    st.subheader('Bulk inventory import')
    st.write('Upload `.xlsx`, `.xls`, or `.csv`. Product is required; Vendor and Release are recommended. Bulk mode creates a report row for every product and target z/OS version.')
    uploaded=st.file_uploader('Choose inventory file', type=['xlsx','xls','csv'], key='inventory')
    if uploaded:
        try:
            inv = pd.read_csv(uploaded) if uploaded.name.lower().endswith('.csv') else pd.read_excel(uploaded)
            st.write(f'{len(inv)} products • {len(inv.columns)} input columns')
            st.dataframe(inv.head(100), use_container_width=True, hide_index=True)
            normalized={str(c).strip().lower():c for c in inv.columns}
            product_col=next((normalized[k] for k in ['product','product name','product_name','software','name'] if k in normalized),None)
            vendor_col=next((normalized[k] for k in ['vendor','manufacturer','company'] if k in normalized),None)
            release_col=next((normalized[k] for k in ['release','version','vrm','product release','product release / version'] if k in normalized),None)
            if not product_col: st.error('Could not identify a Product column. Rename a column to Product and upload again.')
            else:
                if st.button('Validate and create bulk report', type='primary'):
                    output=[]
                    for _,row in inv.iterrows():
                        for version in ZOS_VERSIONS:
                            output.append({'Vendor':str(row.get(vendor_col,'')) if vendor_col else '','Product':str(row.get(product_col,'')),'Release':str(row.get(release_col,'')) if release_col else '', 'z/OS version':version,'Compatible':'Unknown','PTF required / candidates':'Unknown — research not run','APAR candidates':'Unknown','Evidence URL(s)':'','Evidence status':'Not researched','Checked UTC':datetime.now(timezone.utc).isoformat()})
                    st.session_state.compatibility=pd.DataFrame(output)
                    st.success('Bulk matrix prepared. This action validates and expands inventory; it does not claim that each row has been web-researched. Use product lookup and vendor sources for evidence-backed investigations.')
                st.download_button('Download uploaded inventory', inv.to_csv(index=False).encode('utf-8-sig'), 'mvs_bot_input_inventory.csv', 'text/csv')
        except Exception as exc: st.error(f'Unable to read file: {exc}')
    st.markdown('**Input template columns:** `Vendor`, `Product`, `Release`, `Product ID` (optional), `Notes` (optional).')
    template=pd.DataFrame([{'Vendor':'Example vendor','Product':'Example mainframe product','Release':'Exact release','Product ID':'','Notes':'Replace with real data'}])
    st.download_button('Download blank input template', template.to_csv(index=False).encode('utf-8-sig'), 'mvs_bot_input_template.csv', 'text/csv')

with registry_tab:
    st.subheader('Vendor source registry')
    st.caption('Start with known vendors, then add any mainframe ISV. Registry entries are source seeds, not a claim of complete vendor coverage.')
    for name, urls in st.session_state.registry.items():
        with st.expander(f'{name} — {len(urls)} source URL(s)', expanded=False):
            st.code('\n'.join(urls) if urls else 'No source URLs configured')
    st.markdown('#### Add vendor or source')
    new_vendor=st.text_input('Vendor / publisher name', key='new_vendor')
    new_urls=st.text_area('Official source URLs, one per line', key='new_urls')
    if st.button('Save vendor source entries'):
        if not new_vendor.strip(): st.error('Enter a vendor name.')
        else:
            current=st.session_state.registry.get(new_vendor.strip(),[])
            add=[u.strip() for u in new_urls.splitlines() if u.strip().startswith(('http://','https://'))]
            st.session_state.registry[new_vendor.strip()]=list(dict.fromkeys(current+add))
            st.success(f'Saved {len(add)} URL(s) for {new_vendor.strip()}.')
    seed_df=load_seed_data()
    st.markdown('#### Included seed catalogs')
    if not seed_df.empty:
        st.write(f'{len(seed_df)} combined source rows loaded from the supplied CSV catalogs.')
        st.dataframe(seed_df.head(200), use_container_width=True, hide_index=True)
        st.download_button('Download combined seed catalog', seed_df.to_csv(index=False).encode('utf-8-sig'), 'mvs_bot_seed_catalog.csv', 'text/csv')
    else: st.info('No seed CSVs found in the data folder.')

with history_tab:
    st.subheader('Research history (this session)')
    if st.session_state.history:
        hdf=pd.DataFrame(st.session_state.history)
        st.dataframe(hdf, use_container_width=True, hide_index=True)
        st.download_button('Download research history', hdf.to_csv(index=False).encode('utf-8-sig'), 'mvs_bot_research_history.csv', 'text/csv')
    else: st.info('No investigations in this session yet.')
    st.caption('History is held in Streamlit session state in this MVP. Persistent multi-user history requires a database.')

with reports_tab:
    st.subheader('Download report workbook')
    compat=st.session_state.compatibility.copy()
    evidence=st.session_state.evidence.copy()
    m1,m2,m3=st.columns(3)
    m1.metric('Compatibility rows', len(compat))
    m2.metric('Evidence records', len(evidence))
    m3.metric('Research sessions', len(st.session_state.history))
    if compat.empty:
        st.info('Run a lookup or validate an inventory to prepare report rows.')
    else:
        st.dataframe(compat, use_container_width=True, hide_index=True)
        report=workbook_bytes(compat, evidence)
        st.download_button('Download Excel report (.xlsx)', report, 'mvs_bot_compatibility_report.xlsx', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', type='primary')
        st.download_button('Download compatibility CSV', compat.to_csv(index=False).encode('utf-8-sig'), 'mvs_bot_compatibility.csv', 'text/csv')

with st.sidebar:
    st.markdown('## MVS BOT')
    st.caption('Mainframe research workspace')
    st.markdown('**Target platforms**')
    for v in ZOS_VERSIONS: st.markdown(f'- z/OS {v}')
    st.divider()
    st.markdown('**Evidence policy**')
    st.caption('Unknown is a valid result. Never infer compatibility from absence of a warning. PTF candidates require release-specific validation.')
    st.divider()
    st.caption('MVP v1.1 • Local deployment')
